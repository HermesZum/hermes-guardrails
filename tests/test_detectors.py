"""Tests for guardrails.detectors — PII pattern detection."""

import pytest
from guardrails.detectors import scan, scan_for_block, format_findings, has_pii, count_by_severity, Finding, Severity


class TestPhoneDetection:
    def test_international_phone(self):
        findings = scan("Call me at +351555123456")
        kinds = [f.kind for f in findings]
        assert "phone" in kinds

    def test_us_phone(self):
        findings = scan("Phone: (555) 123-4567")
        kinds = [f.kind for f in findings]
        assert "phone" in kinds

    def test_phone_not_in_short_number(self):
        findings = scan("The answer is 42")
        assert all(f.kind != "phone" for f in findings)

    def test_phone_severity_medium(self):
        findings = scan("Call +351555123456")
        phone_findings = [f for f in findings if f.kind == "phone"]
        assert all(f.severity == Severity.MEDIUM for f in phone_findings)


class TestAPIKeyDetection:
    def test_openai_key(self):
        findings = scan("api_key=sk-abc123def456ghi789jkl012mno345pqr")
        assert any(f.kind == "api_key" for f in findings)

    def test_github_token(self):
        findings = scan("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        assert any(f.kind == "api_key" for f in findings)

    def test_aws_key(self):
        findings = scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert any(f.kind == "api_key" for f in findings)

    def test_generic_api_key(self):
        findings = scan('api_key = "abcdefghijklmnopqrstuvwxyz1234567890"')
        assert any(f.kind == "api_key" for f in findings)

    def test_api_key_severity_high(self):
        findings = scan("sk-abc123def456ghi789jkl012mno345pqr")
        key_findings = [f for f in findings if f.kind == "api_key"]
        assert all(f.severity == Severity.HIGH for f in key_findings)

    def test_short_string_not_key(self):
        findings = scan("sk-abc")
        assert all(f.kind != "api_key" for f in findings)


class TestPasswordDetection:
    def test_password_assignment(self):
        findings = scan("password=hunter2securepassword")
        assert any(f.kind == "password" for f in findings)

    def test_passwd_assignment(self):
        findings = scan("passwd: mysecretvalue12345")
        assert any(f.kind == "password" for f in findings)

    def test_password_severity_high(self):
        findings = scan("password=verylongsecretvalue12345678")
        pw_findings = [f for f in findings if f.kind == "password"]
        assert all(f.severity == Severity.HIGH for f in pw_findings)


class TestHostnameDetection:
    def test_local_hostname(self):
        findings = scan("Server at internal.corp.local")
        assert any(f.kind == "hostname" and "internal.corp.local" in f.value for f in findings)

    def test_internal_hostname(self):
        findings = scan("api.internal is up")
        assert any(f.kind == "hostname" for f in findings)

    def test_public_domain_not_flagged(self):
        findings = scan("Visit https://example.com")
        # example.com doesn't end in .local/.internal/.lan etc.
        assert all(f.kind != "hostname" for f in findings)


class TestEmailDetection:
    def test_email(self):
        findings = scan("Contact user@example.com")
        assert any(f.kind == "email" for f in findings)

    def test_email_severity_medium(self):
        findings = scan("user@example.com")
        email_findings = [f for f in findings if f.kind == "email"]
        assert all(f.severity == Severity.MEDIUM for f in email_findings)


class TestIPDetection:
    def test_private_ip(self):
        findings = scan("Server at 192.168.1.1")
        assert any(f.kind == "ip" for f in findings)

    def test_loopback_ip(self):
        findings = scan("Listening on 127.0.0.1")
        assert any(f.kind == "ip" for f in findings)

    def test_public_ip_not_flagged(self):
        findings = scan("IP is 8.8.8.8")
        assert all(f.kind != "ip" for f in findings)

    def test_ip_severity_low(self):
        findings = scan("192.168.1.1")
        ip_findings = [f for f in findings if f.kind == "ip"]
        assert all(f.severity == Severity.LOW for f in ip_findings)


class TestPortDetection:
    def test_port_in_context(self):
        findings = scan("listen 8080")
        assert any(f.kind == "port" for f in findings)

    def test_port_with_colon(self):
        findings = scan("proxy_pass http://upstream:3000")
        assert any(f.kind == "port" for f in findings)

    def test_random_number_not_port(self):
        findings = scan("The count is 1234")
        assert all(f.kind != "port" for f in findings)


class TestSensitivePathDetection:
    def test_ssh_key_path(self):
        findings = scan("Key at .ssh/id_rsa")
        assert any(f.kind == "sensitive_path" for f in findings)

    def test_env_file(self):
        findings = scan("Config in .env")
        assert any(f.kind == "sensitive_path" for f in findings)

    def test_auth_json(self):
        findings = scan("Read auth.json for credentials")
        assert any(f.kind == "sensitive_path" for f in findings)


class TestHexTokenDetection:
    def test_long_hex(self):
        findings = scan("token=abc123def456789012345678901234567890abcd")
        assert any(f.kind == "token" for f in findings)

    def test_short_hex_not_token(self):
        findings = scan("hash=abc123")
        assert all(f.kind != "token" for f in findings)


class TestScanForBlock:
    def test_high_severity_blocks_always(self):
        findings = scan("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        block = scan_for_block("sk-abcdefghijklmnopqrstuvwxyz1234567890", public_repo=False)
        assert len(block) > 0

    def test_medium_severity_blocks_in_public_repo(self):
        text = "Server at internal.corp.local"
        block = scan_for_block(text, public_repo=True)
        assert len(block) > 0

    def test_medium_severity_no_block_private(self):
        text = "Server at internal.corp.local"
        block = scan_for_block(text, public_repo=False)
        assert len(block) == 0


class TestUtilities:
    def test_format_findings(self):
        findings = scan("+351555123456")
        formatted = format_findings(findings)
        assert "phone" in formatted

    def test_has_pii_true(self):
        assert has_pii("+351555123456") is True

    def test_has_pii_false(self):
        assert has_pii("Hello world") is False

    def test_count_by_severity(self):
        text = "sk-abc123def456ghi789jkl012mno345pqr internal.corp.local 192.168.1.1"
        findings = scan(text)
        counts = count_by_severity(findings)
        assert counts["high"] >= 1
        assert counts["medium"] >= 1
        assert counts["low"] >= 1

    def test_masked_api_key(self):
        findings = scan("sk-abc123def456ghi789jkl012mno345pqr")
        key_findings = [f for f in findings if f.kind == "api_key"]
        if key_findings:
            masked = key_findings[0].masked()
            assert "*" in masked
            assert masked.startswith("sk-a")

    def test_empty_text(self):
        assert scan("") == []

    def test_none_safe(self):
        assert scan(None) == []  # type: ignore

    def test_deduplication(self):
        text = "sk-abc123def456ghi789jkl012mno345pqr sk-abc123def456ghi789jkl012mno345pqr"
        findings = scan(text)
        # The two occurrences are at different positions, so both are found
        # But overlapping dedup should prevent triple-counting
        kinds = [f.kind for f in findings if f.kind == "api_key"]
        assert len(kinds) <= 2

def test_ssh_user_prose_does_not_false_positive():
    """Prose like 'SSH account names' or 'ssh login' must NOT trigger."""
    from guardrails.detectors import scan as scan_text

    prose = (
        "The plugin scans SSH account names and login credentials. "
        "Use ssh login for the remote host. Account names are case-sensitive."
    )
    findings = scan_text(prose)
    kinds = [f.kind for f in findings]
    assert "ssh_user" not in kinds, f"prose triggered ssh_user: {findings}"


def test_ssh_user_real_username_still_detected():
    """Real account names (digit/underscore or known) still detected."""
    from guardrails.detectors import scan as scan_text

    text = "ssh hermes_zum@host; user: root; username=deploy"
    findings = scan_text(text)
    kinds = [f.kind for f in findings]
    assert "ssh_user" in kinds
    vals = [f.value for f in findings if f.kind == "ssh_user"]
    assert any("hermes_zum" in v for v in vals), vals
