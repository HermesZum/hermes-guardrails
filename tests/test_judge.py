"""Tests for guardrails.judge — LLM judge for ambiguous cases."""

import pytest
from guardrails.judge import judge_text, JudgeVerdict, _parse_verdict
from guardrails.detectors import scan, Finding, Severity


class TestHighSeverityBlocks:
    def test_high_severity_blocks_without_llm(self):
        findings = scan("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        verdict = judge_text("sk-abcdefghijklmnopqrstuvwxyz1234567890", findings, llm=None)
        assert verdict.sensitive is True
        assert verdict.used_llm is False

    def test_high_severity_blocks_with_llm(self):
        findings = scan("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        verdict = judge_text("sk-abc", findings, llm=object())  # dummy LLM
        assert verdict.sensitive is True
        # Should not even call the LLM for high-severity
        assert verdict.used_llm is False


class TestFailClosed:
    def test_medium_severity_fails_closed_without_llm(self):
        findings = scan("internal.corp.local")
        # Filter to only medium/low (not high)
        medium_findings = [f for f in findings if f.severity != Severity.HIGH]
        verdict = judge_text("internal.corp.local", medium_findings, llm=None)
        assert verdict.sensitive is True
        assert "failing closed" in verdict.reason.lower()

    def test_no_findings_not_sensitive(self):
        verdict = judge_text("Hello world", [], llm=None)
        assert verdict.sensitive is False


class TestParseVerdict:
    def test_parse_clean_json(self):
        result = _parse_verdict('{"sensitive": true, "reason": "phone number"}')
        assert result is not None
        assert result["sensitive"] is True

    def test_parse_json_in_markdown(self):
        result = _parse_verdict('```json\n{"sensitive": false, "reason": "placeholder"}\n```')
        assert result is not None
        assert result["sensitive"] is False

    def test_parse_json_with_extra_text(self):
        result = _parse_verdict('The answer is {"sensitive": true, "reason": "real"} end')
        assert result is not None
        assert result["sensitive"] is True

    def test_parse_garbage_returns_none(self):
        result = _parse_verdict("This is not JSON at all")
        assert result is None


class TestMockLLM:
    """Test with a mock LLM that returns a verdict."""

    class _MockLLM:
        def __init__(self, response: str):
            self._response = response

        def chat(self, messages):
            return self._response

        def complete(self, prompt):
            return self._response

    def test_llm_says_sensitive(self):
        llm = self._MockLLM('{"sensitive": true, "reason": "real phone"}')
        findings = scan("+351555123456")
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        verdict = judge_text("+351555123456", medium, llm=llm)
        assert verdict.sensitive is True
        assert verdict.used_llm is True

    def test_llm_says_not_sensitive(self):
        llm = self._MockLLM('{"sensitive": false, "reason": "placeholder"}')
        findings = scan("+351555123456")
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        verdict = judge_text("+351555123456", medium, llm=llm)
        assert verdict.sensitive is False
        assert verdict.used_llm is True

    def test_llm_returns_garbage_fails_closed(self):
        llm = self._MockLLM("I cannot answer that")
        findings = scan("+351555123456")
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        verdict = judge_text("+351555123456", medium, llm=llm)
        assert verdict.sensitive is True  # fail closed
        assert verdict.used_llm is True

    def test_llm_empty_response_fails_closed(self):
        llm = self._MockLLM("")
        findings = scan("+351555123456")
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        verdict = judge_text("+351555123456", medium, llm=llm)
        assert verdict.sensitive is True  # fail closed


class TestLLMException:
    class _BrokenLLM:
        def chat(self, messages):
            raise RuntimeError("API error")

        def complete(self, prompt):
            raise RuntimeError("API error")

    def test_llm_exception_fails_closed(self):
        llm = self._BrokenLLM()
        findings = scan("+351555123456")
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        verdict = judge_text("+351555123456", medium, llm=llm)
        assert verdict.sensitive is True  # fail closed
        assert "failed" in verdict.reason.lower()