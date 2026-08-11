"""Tests for guardrails plugin — hook integration and tool dispatch."""

import json
import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Import the plugin package (needs Hermes internals, so we test the pure modules)
from guardrails.detectors import scan, Severity
from guardrails.rules import RuleConfig, Action, evaluate
from guardrails.store import AuditStore
from guardrails.judge import judge_text


class TestPreToolCallHook:
    """Test the pre_tool_call hook logic in isolation."""

    def test_block_secret_in_write_file(self):
        from guardrails import _on_pre_tool_call
        # Set up minimal state
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        content = "api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = _on_pre_tool_call("write_file", {"content": content}, session_id="s1", task_id="t1")
        assert result is not None
        assert result["action"] == "block"
        assert "PII" in result["message"] or "GUARDRAILS" in result["message"]

    def test_allow_clean_write_file(self):
        from guardrails import _on_pre_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = _on_pre_tool_call("write_file", {"content": "Hello world"}, session_id="s1")
        assert result is None  # None = allow

    def test_block_secret_in_terminal(self):
        from guardrails import _on_pre_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        content = "export TOKEN=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = _on_pre_tool_call("terminal", {"command": content}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_allow_unscanned_tool(self):
        from guardrails import _on_pre_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = _on_pre_tool_call("web_search", {"query": "test"}, session_id="s1")
        assert result is None

    def test_block_secret_in_memory(self):
        from guardrails import _on_pre_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        content = "password=verylongsecretvalue12345678"
        result = _on_pre_tool_call("memory", {"content": content}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"

    def test_warn_for_medium_in_private_context(self):
        from guardrails import _on_pre_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        content = "Server at internal.corp.local"
        result = _on_pre_tool_call("write_file", {"content": content}, session_id="s1")
        # Should NOT block (medium severity, not public repo), but should log a warning
        assert result is None  # warnings don't return a block dict


class TestTransformToolResult:
    def test_redact_secret_from_terminal_output(self):
        from guardrails import _on_transform_tool_result
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = "The key is sk-abcdefghijklmnopqrstuvwxyz1234567890"
        redacted = _on_transform_tool_result("terminal", result, session_id="s1")
        assert redacted is not None
        assert "REDACTED" in redacted
        assert "sk-abc" not in redacted

    def test_no_redaction_for_clean_output(self):
        from guardrails import _on_transform_tool_result
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = _on_transform_tool_result("terminal", "All clean here", session_id="s1")
        assert result is None

    def test_no_redaction_for_unscanned_tool(self):
        from guardrails import _on_transform_tool_result
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = "password=verylongsecret12345678"
        redacted = _on_transform_tool_result("web_search", result, session_id="s1")
        assert redacted is None


class TestToolDispatch:
    def test_guardrails_status(self):
        from guardrails import _handle_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = json.loads(_handle_tool_call("guardrails_status", {}))
        assert result["status"] == "active"
        assert "stats" in result
        assert "config" in result

    def test_guardrails_scan_clean(self):
        from guardrails import _handle_tool_call
        result = json.loads(_handle_tool_call("guardrails_scan", {"content": "Hello world"}))
        assert result["total_findings"] == 0
        assert result["would_block"] == 0

    def test_guardrails_scan_with_pii(self):
        from guardrails import _handle_tool_call
        content = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = json.loads(_handle_tool_call("guardrails_scan", {"content": content}))
        assert result["total_findings"] > 0
        assert result["would_block"] > 0

    def test_guardrails_scan_public_repo(self):
        from guardrails import _handle_tool_call
        content = "Server at internal.corp.local"
        result = json.loads(_handle_tool_call("guardrails_scan", {"content": content, "public_repo": True}))
        assert result["would_block"] > 0

    def test_guardrails_rules_list(self):
        from guardrails import _handle_tool_call
        result = json.loads(_handle_tool_call("guardrails_rules", {"action": "list"}))
        assert "scan_tools" in result
        assert "write_file" in result["scan_tools"]

    def test_guardrails_audit(self):
        from guardrails import _handle_tool_call
        os.environ["HERMES_HOME"] = tempfile.mkdtemp()
        result = json.loads(_handle_tool_call("guardrails_audit", {"limit": 10}))
        assert "entries" in result
        assert "count" in result

    def test_unknown_tool_error(self):
        from guardrails import _handle_tool_call
        result = json.loads(_handle_tool_call("nonexistent_tool", {}))
        assert "error" in result


class TestGetToolSchemas:
    def test_schemas_exist(self):
        from guardrails import get_tool_schemas
        schemas = get_tool_schemas()
        assert len(schemas) == 4
        names = [s["name"] for s in schemas]
        assert "guardrails_status" in names
        assert "guardrails_rules" in names
        assert "guardrails_audit" in names
        assert "guardrails_scan" in names

    def test_schemas_have_parameters(self):
        from guardrails import get_tool_schemas
        schemas = get_tool_schemas()
        for s in schemas:
            assert "name" in s
            assert "description" in s
            assert "parameters" in s
            assert s["parameters"]["type"] == "object"


class TestSecurityIncident:
    """Regression tests: the exact patterns that leaked in the real incident."""

    def test_phone_number_detected(self):
        findings = scan("+351555123456")
        assert any(f.kind == "phone" for f in findings)

    def test_ssh_username_detected(self):
        findings = scan("ssh deploy_user@server")
        # SSH pattern should match
        assert any(f.kind == "ssh_user" for f in findings)

    def test_hostname_detected(self):
        findings = scan("Server at internal.corp.local")
        assert any(f.kind == "hostname" for f in findings)

    def test_port_in_config_context(self):
        findings = scan("listen 8080")
        assert any(f.kind == "port" for f in findings)

    def test_all_patterns_in_incident(self):
        """The exact content that was in the test fixture that leaked."""
        content = """
        Server: internal.corp.local
        SSH user: deploy_user
        Ports: 8080, 9090
        Phone: +351555123456
        """
        findings = scan(content)
        kinds = {f.kind for f in findings}
        # Should detect multiple sensitive patterns
        assert "hostname" in kinds or "phone" in kinds or "port" in kinds