"""
Rule engine for Hermes guardrails.

Maps tool calls to scan rules and decides what action to take
(block, warn, allow) based on detected findings and context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .detectors import Finding, Severity, scan, scan_for_block, format_findings


class Action(str, Enum):
    BLOCK = "block"    # prevent the tool call entirely
    WARN = "warn"       # let it through but log a warning
    ALLOW = "allow"     # no findings, let it through


@dataclass
class ScanResult:
    """Result of scanning a tool call."""
    action: Action
    findings: list[Finding] = field(default_factory=list)
    message: str = ""

    @property
    def should_block(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def should_warn(self) -> bool:
        return self.action == Action.WARN


@dataclass
class RuleConfig:
    """Configuration for the rule engine."""
    # Tools whose content gets scanned before execution
    scan_tools: set[str] = field(default_factory=lambda: {
        "write_file", "patch", "terminal", "memory",
    })
    # Tools whose output gets sanitized
    redact_tools: set[str] = field(default_factory=lambda: {
        "terminal", "read_file",
    })
    # Public repos (extra scrutiny — medium-severity findings also block)
    public_repos: set[str] = field(default_factory=set)
    # If True, block when LLM judge is unavailable. If False, warn only.
    fail_closed: bool = True
    # If True, scan terminal commands for git push/commit to public repos
    scan_git: bool = True
    # If True, scan memory writes for secrets
    scan_memory: bool = True
    # Maximum content length to scan (chars) — avoid scanning huge files
    max_scan_length: int = 500_000


# Git commands that write to a repo (commit, push, add)
_GIT_WRITE_RE = None  # set lazily

def _git_write_regex():
    global _GIT_WRITE_RE
    if _GIT_WRITE_RE is None:
        import re
        _GIT_WRITE_RE = re.compile(
            r"\bgit\s+(?:push|commit|add|merge|rebase|cherry-pick|am)\b",
            re.IGNORECASE,
        )
    return _GIT_WRITE_RE


def evaluate(
    tool_name: str,
    args: dict,
    config: RuleConfig,
) -> ScanResult:
    """
    Evaluate a tool call against guardrail rules.

    Args:
        tool_name: The name of the tool being called.
        args: The tool's arguments dict.
        config: The rule configuration.

    Returns:
        ScanResult with the action to take and any findings.
    """
    if tool_name not in config.scan_tools:
        return ScanResult(action=Action.ALLOW)

    # Extract the content to scan based on tool type
    content = _extract_content(tool_name, args)
    if not content or len(content) > config.max_scan_length:
        return ScanResult(action=Action.ALLOW)

    # Determine if we're in a public-repo context
    public_repo = _is_public_repo_context(tool_name, args, content, config)

    # Check for git writes to public repos
    if tool_name == "terminal" and config.scan_git:
        git_match = _git_write_regex().search(content)
        if git_match and public_repo:
            # In public-repo git context, medium-severity findings also block
            block_findings = scan_for_block(content, public_repo=True)
            if block_findings:
                return ScanResult(
                    action=Action.BLOCK,
                    findings=block_findings,
                    message=_build_block_message(block_findings, "git write to public repo"),
                )

    # Memory writes: scan for secrets (always block)
    if tool_name == "memory" and config.scan_memory:
        block_findings = scan_for_block(content, public_repo=False)
        if block_findings:
            return ScanResult(
                action=Action.BLOCK,
                findings=block_findings,
                message=_build_block_message(block_findings, "memory write"),
            )

    # General scan
    block_findings = scan_for_block(content, public_repo=public_repo)
    if block_findings:
        return ScanResult(
            action=Action.BLOCK,
            findings=block_findings,
            message=_build_block_message(block_findings, tool_name),
        )

    # Check for warnings (medium/low severity in non-public context)
    all_findings = scan(content)
    warn_findings = [
        f for f in all_findings
        if f.severity in (Severity.MEDIUM, Severity.LOW) and f not in block_findings
    ]
    if warn_findings:
        return ScanResult(
            action=Action.WARN,
            findings=warn_findings,
            message=_build_warn_message(warn_findings, tool_name),
        )

    return ScanResult(action=Action.ALLOW)


def evaluate_output(
    tool_name: str,
    result: str,
    config: RuleConfig,
) -> str:
    """
    Evaluate tool output and return sanitized version.

    Returns the result with secrets redacted, or the original if no findings.
    """
    if tool_name not in config.redact_tools:
        return result

    if not result or len(result) > config.max_scan_length:
        return result

    findings = scan(result)
    if not findings:
        return result

    # Redact high-severity findings (secrets, tokens, passwords)
    redacted = result
    for f in findings:
        if f.severity == Severity.HIGH:
            redacted = redacted.replace(f.value, f"***REDACTED:{f.kind}***")

    return redacted


def _extract_content(tool_name: str, args: dict) -> str:
    """Extract the text content to scan from tool arguments."""
    if tool_name == "write_file":
        return args.get("content", "") or ""
    if tool_name == "patch":
        # Patch has old_string and new_string
        parts = []
        for key in ("old_string", "new_string", "patch"):
            val = args.get(key, "")
            if val:
                parts.append(val)
        return "\n".join(parts)
    if tool_name == "terminal":
        return args.get("command", "") or ""
    if tool_name == "memory":
        # Memory tool has content field
        return args.get("content", "") or ""
    # Generic: scan all string values in args
    parts = []
    for val in args.values():
        if isinstance(val, str):
            parts.append(val)
    return "\n".join(parts)


def _is_public_repo_context(
    tool_name: str,
    args: dict,
    content: str,
    config: RuleConfig,
) -> bool:
    """Check if the operation targets a public repo."""
    if not config.public_repos:
        return False

    # Check if any public repo name appears in the content
    for repo in config.public_repos:
        if repo in content:
            return True

    # Check if the path/command references a public repo directory
    # (match full "org/repo" OR the bare directory basename, e.g.
    #  /root/hermes-guardrails/... for agent-community/hermes-guardrails)
    for key in ("path", "workdir"):
        val = args.get(key, "")
        if not val:
            continue
        for repo in config.public_repos:
            if repo in val:
                return True
            basename = repo.split("/")[-1]
            if basename and basename in val.split("/"):
                return True

    return False


def _build_block_message(findings: list[Finding], context: str) -> str:
    """Build a human-readable block message for the LLM."""
    lines = [
        f"GUARDRAILS: Blocked {context} — PII/sensitive data detected:",
        format_findings(findings),
        "Use fictional placeholders instead. Never commit real environment data.",
    ]
    return "\n".join(lines)


def _build_warn_message(findings: list[Finding], context: str) -> str:
    """Build a warning message (not blocked, but logged)."""
    lines = [
        f"GUARDRAILS: Warning for {context} — sensitive patterns detected (not blocked):",
        format_findings(findings),
    ]
    return "\n".join(lines)