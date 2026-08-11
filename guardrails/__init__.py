"""
Hermes Guardrails plugin — PII detection, code safety, audit logging.

Hooks:
  - pre_tool_call:        blocks writes/commands with PII before execution
  - post_tool_call:       logs all tool calls to audit DB
  - transform_tool_result: redacts secrets from tool output

Tools:
  - guardrails_status:    detection stats and blocked counts
  - guardrails_rules:     list/update detection rules
  - guardrails_audit:     view blocked attempts and audit log
  - guardrails_scan:      manually scan content for PII
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

from .detectors import scan, format_findings, count_by_severity, Finding, Severity
from .rules import RuleConfig, ScanResult, Action, evaluate, evaluate_output
from .judge import judge_text, JudgeVerdict
from .store import AuditStore

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_PLUGIN_NAME = "guardrails"
_DB_DIR = "guardrails"
_DB_FILE = "guardrails.db"

# ---------------------------------------------------------------------------
# Plugin state (singleton, initialized in register())
# ---------------------------------------------------------------------------

_store: Optional[AuditStore] = None
_config: Optional[RuleConfig] = None
_llm = None
_lock = threading.Lock()


def _get_store() -> Optional[AuditStore]:
    return _store


def _get_config() -> RuleConfig:
    global _config
    if _config is None:
        _config = RuleConfig()
    return _config


def _resolve_db_path() -> Path:
    home = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
    return Path(home) / _DB_DIR / _DB_FILE


def _ensure_store() -> Optional[AuditStore]:
    global _store
    with _lock:
        if _store is None:
            _store = AuditStore(_resolve_db_path())
            try:
                _store.connect()
            except Exception as e:
                logger.error(f"guardrails: failed to connect audit store: {e}")
                _store = None
        return _store


# ---------------------------------------------------------------------------
# Hook callbacks
# ---------------------------------------------------------------------------

def _on_pre_tool_call(tool_name: str, args: dict, **kw) -> Optional[dict]:
    """pre_tool_call hook — blocks tool calls with PII."""
    config = _get_config()

    if tool_name not in config.scan_tools:
        return None

    # Evaluate against rules
    result = evaluate(tool_name, args or {}, config)

    store = _ensure_store()

    if result.should_block:
        # Log the block
        if store:
            store.log(
                tool_name=tool_name,
                action="blocked",
                severity="high",
                findings=result.findings,
                message=result.message,
                session_id=kw.get("session_id", ""),
                task_id=kw.get("task_id", ""),
            )
        logger.info(f"guardrails: BLOCKED {tool_name} — {len(result.findings)} finding(s)")
        return {"action": "block", "message": result.message}

    if result.should_warn:
        # Log the warning but allow through
        if store:
            store.log(
                tool_name=tool_name,
                action="warned",
                severity="medium",
                findings=result.findings,
                message=result.message,
                session_id=kw.get("session_id", ""),
                task_id=kw.get("task_id", ""),
            )
        logger.info(f"guardrails: WARNED {tool_name} — {len(result.findings)} finding(s)")
        return None  # allow through

    # No findings — log as allowed
    if store:
        store.log(
            tool_name=tool_name,
            action="allowed",
            severity="info",
            findings=[],
            message="",
            session_id=kw.get("session_id", ""),
            task_id=kw.get("task_id", ""),
        )
    return None


def _on_post_tool_call(tool_name: str, args: dict, result: str, **kw) -> None:
    """post_tool_call hook — logs tool calls to audit log (observational)."""
    store = _ensure_store()
    if store and tool_name in _get_config().scan_tools:
        # Only log if not already logged by pre_tool_call
        findings = scan(_extract_for_log(tool_name, args))
        if findings:
            store.log(
                tool_name=tool_name,
                action="scanned",
                severity="low",
                findings=findings,
                message=f"post_tool_call: {len(findings)} pattern(s) in args",
                session_id=kw.get("session_id", ""),
                task_id=kw.get("task_id", ""),
            )


def _on_transform_tool_result(tool_name: str, result: str, **kw) -> Optional[str]:
    """transform_tool_result hook — redacts secrets from tool output."""
    config = _get_config()
    if tool_name not in config.redact_tools:
        return None

    if not result or len(result) > config.max_scan_length:
        return None

    redacted = evaluate_output(tool_name, result, config)
    if redacted != result:
        store = _ensure_store()
        if store:
            store.log(
                tool_name=tool_name,
                action="redacted",
                severity="high",
                findings=scan(result),
                message="secrets redacted from tool output",
                session_id=kw.get("session_id", ""),
                task_id=kw.get("task_id", ""),
            )
        logger.info(f"guardrails: REDACTED secrets from {tool_name} output")
        return redacted

    return None


def _extract_for_log(tool_name: str, args: dict) -> str:
    """Extract content from args for logging (same as rules._extract_content)."""
    if tool_name == "write_file":
        return args.get("content", "") or ""
    if tool_name == "patch":
        return "\n".join(args.get(k, "") for k in ("old_string", "new_string", "patch") if args.get(k))
    if tool_name == "terminal":
        return args.get("command", "") or ""
    if tool_name == "memory":
        return args.get("content", "") or ""
    return ""


# ---------------------------------------------------------------------------
# Agent tools
# ---------------------------------------------------------------------------

_TOOL_SCHEMAS = [
    {
        "name": "guardrails_status",
        "description": "Show guardrails detection stats, blocked counts, and recent activity summary.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "guardrails_rules",
        "description": "List, enable, or disable guardrail detection rules. View current configuration.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "enable", "disable"],
                    "description": "List rules, or enable/disable a specific tool scan.",
                    "default": "list",
                },
                "tool": {
                    "type": "string",
                    "description": "Tool name to enable/disable scanning for (e.g. 'write_file', 'terminal').",
                },
            },
        },
    },
    {
        "name": "guardrails_audit",
        "description": "View the guardrails audit log — blocked attempts, warnings, and redacted outputs.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max entries to return (1-500).",
                    "default": 50,
                },
                "action_filter": {
                    "type": "string",
                    "enum": ["blocked", "warned", "allowed", "redacted", "scanned", ""],
                    "description": "Filter by action type. Empty = all.",
                    "default": "",
                },
            },
        },
    },
    {
        "name": "guardrails_scan",
        "description": "Manually scan content for PII and sensitive data. Useful for reviewing files before commit.",
        "parameters": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "The text content to scan.",
                },
                "public_repo": {
                    "type": "boolean",
                    "description": "If True, medium-severity findings also flag (public-repo context).",
                    "default": False,
                },
            },
            "required": ["content"],
        },
    },
]


def _handle_tool_call(name: str, args: dict) -> str:
    """Dispatch agent tool calls."""
    try:
        if name == "guardrails_status":
            return _handle_status(args)
        if name == "guardrails_rules":
            return _handle_rules(args)
        if name == "guardrails_audit":
            return _handle_audit(args)
        if name == "guardrails_scan":
            return _handle_scan(args)
        return json.dumps({"error": f"unknown tool: {name}"})
    except Exception as e:
        logger.error(f"guardrails: tool {name} failed: {e}")
        return json.dumps({"error": str(e)})


def _handle_status(args: dict) -> str:
    store = _ensure_store()
    config = _get_config()
    stats = store.get_stats() if store else {}
    blocked = stats.get("total_blocked", 0)
    warned = stats.get("total_warned", 0)
    allowed = stats.get("total_allowed", 0)
    return json.dumps({
        "status": "active",
        "stats": {
            "total_blocked": blocked,
            "total_warned": warned,
            "total_allowed": allowed,
            "total_scanned": stats.get("total_scanned", 0),
        },
        "config": {
            "scan_tools": sorted(config.scan_tools),
            "redact_tools": sorted(config.redact_tools),
            "public_repos": sorted(config.public_repos),
            "fail_closed": config.fail_closed,
            "scan_git": config.scan_git,
            "scan_memory": config.scan_memory,
        },
    }, indent=2)


def _handle_rules(args: dict) -> str:
    config = _get_config()
    action = args.get("action", "list")
    tool = args.get("tool", "")

    if action == "list":
        return json.dumps({
            "scan_tools": sorted(config.scan_tools),
            "redact_tools": sorted(config.redact_tools),
            "public_repos": sorted(config.public_repos),
            "fail_closed": config.fail_closed,
        }, indent=2)

    if action == "enable" and tool:
        config.scan_tools.add(tool)
        return json.dumps({"ok": True, "message": f"enabled scanning for {tool}"})

    if action == "disable" and tool:
        config.scan_tools.discard(tool)
        return json.dumps({"ok": True, "message": f"disabled scanning for {tool}"})

    return json.dumps({"error": "invalid action/tool"})


def _handle_audit(args: dict) -> str:
    store = _ensure_store()
    if not store:
        return json.dumps({"error": "audit store not available"})
    limit = max(1, min(int(args.get("limit", 50)), 500))
    action_filter = args.get("action_filter", "")
    entries = store.get_recent(limit=limit, action_filter=action_filter)
    return json.dumps({
        "entries": entries,
        "count": len(entries),
    }, indent=2)


def _handle_scan(args: dict) -> str:
    content = args.get("content", "")
    public_repo = args.get("public_repo", False)
    findings = scan(content)
    block_findings = [f for f in findings if f.severity == Severity.HIGH] if not public_repo \
        else [f for f in findings if f.severity in (Severity.HIGH, Severity.MEDIUM)]
    return json.dumps({
        "total_findings": len(findings),
        "would_block": len(block_findings),
        "by_severity": count_by_severity(findings),
        "findings": [
            {
                "kind": f.kind,
                "severity": f.severity.value,
                "masked_value": f.masked(),
                "context": f.context,
            }
            for f in findings
        ],
    }, indent=2)


def get_tool_schemas() -> list[dict]:
    """Return tool schemas for the agent."""
    return _TOOL_SCHEMAS


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

def register(ctx) -> None:
    """Register hooks and tools with Hermes."""
    global _llm, _config

    # Try to get the LLM facade
    try:
        _llm = ctx.llm
    except Exception:
        _llm = None

    # Load config from config.yaml (guardrails block)
    try:
        import yaml
        config_path = Path(os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))) / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                full_config = yaml.safe_load(f) or {}
            gr_config = full_config.get("guardrails", {})
            _config = RuleConfig(
                scan_tools=set(gr_config.get("scan_tools", ["write_file", "patch", "terminal", "memory"])),
                redact_tools=set(gr_config.get("redact_tools", ["terminal", "read_file"])),
                public_repos=set(gr_config.get("public_repos", [])),
                fail_closed=gr_config.get("fail_closed", True),
                scan_git=gr_config.get("scan_git", True),
                scan_memory=gr_config.get("scan_memory", True),
            )
    except Exception as e:
        logger.warning(f"guardrails: could not load config, using defaults: {e}")
        _config = RuleConfig()

    # Register hooks
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)

    # Register tools
    for schema in _TOOL_SCHEMAS:
        ctx.register_tool(
            name=schema["name"],
            toolset="guardrails",
            schema=schema,
            handler=_make_dispatcher(schema["name"]),
            check_fn=lambda: True,
        )

    # Initialize the audit store
    _ensure_store()

    logger.info("guardrails: registered 4 tools + 3 hooks (pre_tool_call, post_tool_call, transform_tool_result)")


def _make_dispatcher(tool_name: str):
    """Create a dispatch closure for a tool."""
    def _dispatch(args, **kwargs):
        return _handle_tool_call(tool_name, args)
    return _dispatch