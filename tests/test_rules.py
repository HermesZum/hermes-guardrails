"""Tests for guardrails.rules — rule engine."""

import pytest
from guardrails.rules import RuleConfig, ScanResult, Action, evaluate, evaluate_output


class TestEvaluateWriteFile:
    def test_clean_content_allowed(self):
        config = RuleConfig()
        result = evaluate("write_file", {"content": "Hello world"}, config)
        assert result.action == Action.ALLOW

    def test_api_key_blocked(self):
        config = RuleConfig()
        content = "API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = evaluate("write_file", {"content": content}, config)
        assert result.should_block

    def test_phone_in_public_repo_blocked(self):
        config = RuleConfig(public_repos={"myorg/myrepo"})
        content = "Call +351555123456 in myorg/myrepo"
        result = evaluate("write_file", {"content": content}, config)
        assert result.should_block

    def test_phone_not_blocked_in_private_context(self):
        config = RuleConfig()
        content = "Call +351555123456"
        result = evaluate("write_file", {"content": content}, config)
        # Medium severity, not public repo — should warn, not block
        assert not result.should_block

    def test_hostname_warned_in_private_context(self):
        config = RuleConfig()
        content = "Server at internal.corp.local"
        result = evaluate("write_file", {"content": content}, config)
        # Medium severity, not public repo — should warn
        assert result.should_warn

    def test_empty_content_allowed(self):
        config = RuleConfig()
        result = evaluate("write_file", {"content": ""}, config)
        assert result.action == Action.ALLOW


class TestEvaluateTerminal:
    def test_clean_command_allowed(self):
        config = RuleConfig()
        result = evaluate("terminal", {"command": "ls -la"}, config)
        assert result.action == Action.ALLOW

    def test_git_push_with_pii_to_public_repo(self):
        config = RuleConfig(public_repos={"myorg/myrepo"})
        content = "git push myorg/myrepo && echo +351555123456"
        result = evaluate("terminal", {"command": content}, config)
        assert result.should_block

    def test_secret_in_command_blocked(self):
        config = RuleConfig()
        content = "export TOKEN=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = evaluate("terminal", {"command": content}, config)
        assert result.should_block


class TestEvaluateMemory:
    def test_secret_in_memory_blocked(self):
        config = RuleConfig()
        content = "password=mysecretvalue12345678"
        result = evaluate("memory", {"content": content}, config)
        assert result.should_block

    def test_clean_memory_allowed(self):
        config = RuleConfig()
        result = evaluate("memory", {"content": "User prefers concise responses"}, config)
        assert result.action == Action.ALLOW


class TestEvaluatePatch:
    def test_secret_in_patch_blocked(self):
        config = RuleConfig()
        content = "api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = evaluate("patch", {"old_string": "old", "new_string": content}, config)
        assert result.should_block

    def test_clean_patch_allowed(self):
        config = RuleConfig()
        result = evaluate("patch", {"old_string": "old", "new_string": "new"}, config)
        assert result.action == Action.ALLOW


class TestNonScanTool:
    def test_unscanned_tool_allowed(self):
        config = RuleConfig()
        result = evaluate("read_file", {"path": "/etc/passwd"}, config)
        assert result.action == Action.ALLOW

    def test_web_search_allowed(self):
        config = RuleConfig()
        result = evaluate("web_search", {"query": "internal.corp.local ssh"}, config)
        assert result.action == Action.ALLOW


class TestEvaluateOutput:
    def test_redact_secret_from_output(self):
        config = RuleConfig()
        result = "The key is sk-abcdefghijklmnopqrstuvwxyz1234567890"
        redacted = evaluate_output("terminal", result, config)
        assert "REDACTED" in redacted
        assert "sk-abc" not in redacted

    def test_no_redaction_for_clean_output(self):
        config = RuleConfig()
        result = "All good, no secrets here"
        redacted = evaluate_output("terminal", result, config)
        assert redacted == result

    def test_no_redaction_for_unscanned_tool(self):
        config = RuleConfig()
        result = "password=hunter2verylongpassword123"
        redacted = evaluate_output("web_search", result, config)
        assert redacted == result


class TestMaxScanLength:
    def test_oversized_content_allowed(self):
        config = RuleConfig(max_scan_length=100)
        content = "x" * 200
        result = evaluate("write_file", {"content": content}, config)
        assert result.action == Action.ALLOW


class TestBlockMessage:
    def test_block_message_contains_kind(self):
        config = RuleConfig()
        content = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = evaluate("write_file", {"content": content}, config)
        assert "api_key" in result.message.lower() or "guardrails" in result.message.lower()

    def test_block_message_contains_instruction(self):
        config = RuleConfig()
        content = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = evaluate("write_file", {"content": content}, config)
        assert "fictional" in result.message.lower() or "placeholder" in result.message.lower()