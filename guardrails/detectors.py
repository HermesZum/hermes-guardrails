"""
Pattern-based PII detection for Hermes guardrails.

All detection is regex-based and runs in <1ms. No LLM needed for the
common cases (phone numbers, hostnames, API keys, SSH usernames, tokens).

Each detector returns a list of Finding namedtuples with:
- kind: what was detected (e.g. "phone", "hostname", "api_key")
- value: the matched string
- position: (start, end) offset in the scanned text
- severity: "high", "medium", or "low"
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    HIGH = "high"      # secrets, API keys, passwords — always block
    MEDIUM = "medium"  # phone numbers, hostnames, usernames — block in public-repo context
    LOW = "low"        # port numbers, IP addresses — warn only


@dataclass(frozen=True)
class Finding:
    """A single PII detection result."""
    kind: str           # phone, hostname, api_key, ssh_user, port, ip, email, token
    value: str          # the matched text (may be masked in output)
    position: tuple[int, int]
    severity: Severity
    context: str = ""   # ~40 chars surrounding the match, for the judge

    def masked(self) -> str:
        """Return the value with sensitive parts masked for logging."""
        if self.kind in ("api_key", "token", "password"):
            if len(self.value) <= 8:
                return "*" * len(self.value)
            return self.value[:4] + "*" * (len(self.value) - 4)
        if self.kind == "phone":
            if len(self.value) <= 4:
                return self.value
            return self.value[:4] + "*" * (len(self.value) - 4)
        return self.value


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Phone numbers: international format +CC..., or US (XXX) XXX-XXXX
_PHONE_RE = re.compile(
    r"""
    (?:\+[\d\s.-]{9,18})          # international: +351 933 433 443
    | (?:\(\d{3}\)\s*\d{3}[\s.-]?\d{4})  # US: (555) 123-4567
    """,
    re.VERBOSE,
)

# Hostnames: FQDNs ending in .local, .internal, or known private patterns
_HOSTNAME_RE = re.compile(
    r"""
    \b(
        (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
        (?:local|internal|lan|home|corp|priv)
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# API keys: common prefixes from major providers
_API_KEY_PATTERNS = [
    ("openai",    re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b")),
    ("github",    re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36,}\b")),
    ("slack",     re.compile(r"\bxox[baprs]-[a-zA-Z0-9-]{10,}\b")),
    ("aws",       re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("stripe",    re.compile(r"\bsk_(?:test_)?[a-zA-Z0-9]{20,}\b")),
    ("generic",   re.compile(r"""\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)["'"\s:=]+([a-zA-Z0-9_-]{20,})\b""", re.IGNORECASE)),
]

# SSH usernames: word characters near ssh/user keywords
_SSH_USER_RE = re.compile(
    r"""
    (?:ssh\s+(?:-l\s+)?(\w+)|user(?:name)?[=:]\s*(\w+))
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Known common account names — always treated as credentials when captured.
_KNOWN_USERNAMES = {
    "root", "admin", "deploy", "ubuntu", "ec2-user", "pi", "git",
    "postgres", "www-data", "nobody", "hermes", "agent", "oracle",
}


def _looks_like_username(name: str) -> bool:
    """True if the captured word looks like a real account name.

    Accepts known common usernames, or any word containing a digit or
    underscore (e.g. ``hermes_zum``, ``user123``). Rejects prose words
    like "account" or "login".
    """
    if not name:
        return False
    if name.lower() in _KNOWN_USERNAMES:
        return True
    return any(ch.isdigit() or ch == "_" for ch in name)


# Email addresses
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Private IP addresses (RFC 1918 + loopback + link-local)
_IP_RE = re.compile(
    r"""
    \b(
        (?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})
        | (?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})
        | (?:192\.168\.\d{1,3}\.\d{1,3})
        | (?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})
    )\b
    """,
    re.VERBOSE,
)

# Port numbers near port/service keywords
_PORT_CONTEXT_RE = re.compile(
    r"""
    (?:port|listen|proxy_pass|server_name|upstream|:\s*)
    \s*
    (\d{4,5})
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Long hex strings (potential tokens/secrets)
_HEX_TOKEN_RE = re.compile(r"\b[0-9a-f]{40,}\b", re.IGNORECASE)

# Password assignments
_PASSWORD_RE = re.compile(
    r"""
    (?:password|passwd|pwd|secret|auth[_-]?token)
    \s*[=:]\s*
    (\S+)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Known sensitive file paths
_SENSITIVE_PATH_RE = re.compile(
    r"""
    (
        \.ssh/[a-z_]+
        | \.env(?:\.\w+)?
        | auth\.json
        | credentials\.json
        | \.netrc
        | \.pgpass
    )
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _extract_context(text: str, start: int, end: int, width: int = 40) -> str:
    """Extract ~width chars of context around a match."""
    ctx_start = max(0, start - width)
    ctx_end = min(len(text), end + width)
    return text[ctx_start:ctx_end].replace("\n", " ").strip()


def scan(text: str) -> list[Finding]:
    """
    Scan text for PII patterns. Returns a list of Finding objects.

    This is the primary entry point. Runs all pattern detectors and
    returns deduplicated findings sorted by position.
    """
    if not text:
        return []

    findings: list[Finding] = []
    seen_spans: set[tuple[int, int]] = set()

    def _add(kind: str, match: re.Match, severity: Severity, group: int = 0) -> None:
        start, end = match.span(group)
        if start == end:
            return
        # Deduplicate overlapping spans (keep higher severity)
        span = (start, end)
        for existing_start, existing_end in seen_spans:
            if start < existing_end and existing_start < end:
                # Overlap — skip if existing already covers this
                if existing_start <= start and end <= existing_end:
                    return
        seen_spans.add(span)
        findings.append(Finding(
            kind=kind,
            value=match.group(group),
            position=(start, end),
            severity=severity,
            context=_extract_context(text, start, end),
        ))

    # Phone numbers (medium — context-dependent)
    for m in _PHONE_RE.finditer(text):
        _add("phone", m, Severity.MEDIUM)

    # API keys (high — always block)
    for provider, pattern in _API_KEY_PATTERNS:
        for m in pattern.finditer(text):
            _add("api_key", m, Severity.HIGH, group=0 if provider != "generic" else 0)
            # For generic, the actual key is group 1
            if provider == "generic" and m.lastindex and m.lastindex >= 1:
                # Re-add with the actual key value
                findings.pop()
                seen_spans.discard((m.start(0), m.end(0)))
                _add("api_key", m, Severity.HIGH, group=1)

    # Passwords (high — always block)
    for m in _PASSWORD_RE.finditer(text):
        _add("password", m, Severity.HIGH, group=1)

    # SSH usernames (medium — context-dependent)
    for m in _SSH_USER_RE.finditer(text):
        group = 1 if m.group(1) else 2
        name = m.group(group) or ""
        if not _looks_like_username(name):
            continue
        _add("ssh_user", m, Severity.MEDIUM, group=group)

    # Hostnames (medium — context-dependent)
    for m in _HOSTNAME_RE.finditer(text):
        _add("hostname", m, Severity.MEDIUM)

    # Email addresses (medium — contains personal identifier)
    for m in _EMAIL_RE.finditer(text):
        _add("email", m, Severity.MEDIUM)

    # Private IPs (low — informational)
    for m in _IP_RE.finditer(text):
        _add("ip", m, Severity.LOW)

    # Port numbers in context (low — informational)
    for m in _PORT_CONTEXT_RE.finditer(text):
        _add("port", m, Severity.LOW, group=1)

    # Long hex tokens (high — potential secret)
    for m in _HEX_TOKEN_RE.finditer(text):
        _add("token", m, Severity.HIGH)

    # Sensitive file paths (medium — leaks infrastructure)
    for m in _SENSITIVE_PATH_RE.finditer(text):
        _add("sensitive_path", m, Severity.MEDIUM)

    # Sort by position
    findings.sort(key=lambda f: f.position[0])
    return findings


def scan_for_block(text: str, public_repo: bool = False) -> list[Finding]:
    """
    Scan text and return only findings that should trigger a block.

    Args:
        text: The text to scan.
        public_repo: If True, medium-severity findings also block
                     (phone numbers, hostnames, etc. in public-repo context).
                     If False, only high-severity findings block.

    Returns:
        List of findings that should trigger a block.
    """
    all_findings = scan(text)
    if public_repo:
        # Block on high + medium in public-repo context
        return [f for f in all_findings if f.severity in (Severity.HIGH, Severity.MEDIUM)]
    # Block on high only (secrets, API keys, passwords, tokens)
    return [f for f in all_findings if f.severity == Severity.HIGH]


def format_findings(findings: list[Finding]) -> str:
    """Format findings for display in block messages and logs."""
    if not findings:
        return ""
    lines = []
    for f in findings:
        lines.append(f"  [{f.severity.value}] {f.kind}: {f.masked()}")
        if f.context:
            lines.append(f"    context: ...{f.context}...")
    return "\n".join(lines)


def has_pii(text: str) -> bool:
    """Quick check: does the text contain any PII at all?"""
    return len(scan(text)) > 0


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity level."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts