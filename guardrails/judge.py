"""
LLM judge for ambiguous PII cases.

Used when pattern-based detection finds something but it's unclear
whether it's actually sensitive (e.g. a number that could be a port
or a zip code, or a word that looks like a username but is just prose).

The judge uses ctx.llm (the host's model). It MUST fail CLOSED:
if the LLM is unavailable, the judge returns "sensitive" (block).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from .detectors import Finding

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

JUDGE_PROMPT = """You are a security classifier. Analyze the following text snippet and determine
if it contains sensitive personal or infrastructure data that should NOT be written to
a public repository or agent memory file.

Sensitive data includes:
- Real phone numbers (not fictional placeholders)
- Real SSH usernames or hostnames
- API keys, tokens, passwords, secrets
- Real IP addresses of private infrastructure
- Real email addresses
- Internal port numbers in infrastructure config context

NOT sensitive:
- Fictional placeholder values (e.g. "user@example.com", "127.0.0.1")
- Generic documentation examples
- Code patterns that just happen to look like tokens (e.g. hex hashes in test fixtures)
- Port numbers in public documentation (e.g. "HTTP uses port 80")

Text to analyze:
---
{text}
---

Detected patterns:
{patterns}

Respond with EXACTLY this JSON format (no markdown, no explanation):
{{"sensitive": true/false, "reason": "brief explanation"}}"""


@dataclass
class JudgeVerdict:
    """Result of the LLM judge evaluation."""
    sensitive: bool
    reason: str = ""
    used_llm: bool = False  # False = static fallback was used


def judge_text(
    text: str,
    findings: list[Finding],
    llm=None,
) -> JudgeVerdict:
    """
    Judge whether detected patterns are actually sensitive.

    Args:
        text: The full text being scanned.
        findings: The findings from pattern-based detection.
        llm: A PluginLlm facade (from ctx.llm). If None, fail CLOSED.

    Returns:
        JudgeVerdict with the decision.
    """
    if not findings:
        return JudgeVerdict(sensitive=False, reason="no findings", used_llm=False)

    # If any HIGH-severity finding, block without LLM — these are unambiguous
    high_findings = [f for f in findings if f.severity.value == "high"]
    if high_findings:
        return JudgeVerdict(
            sensitive=True,
            reason=f"high-severity pattern detected: {', '.join(f.kind for f in high_findings)}",
            used_llm=False,
        )

    # For medium/low findings, use the LLM judge if available
    if llm is None:
        # Fail CLOSED: treat as sensitive when LLM is unavailable
        logger.warning("guardrails-judge: LLM unavailable, failing CLOSED (treating as sensitive)")
        return JudgeVerdict(
            sensitive=True,
            reason="LLM judge unavailable — failing closed",
            used_llm=False,
        )

    patterns_text = "\n".join(f"- [{f.severity.value}] {f.kind}: {f.masked()}" for f in findings)
    prompt = JUDGE_PROMPT.format(text=text[:2000], patterns=patterns_text)

    try:
        response = _call_llm(llm, prompt)
        if not response:
            return JudgeVerdict(
                sensitive=True,
                reason="LLM returned empty response — failing closed",
                used_llm=True,
            )

        verdict = _parse_verdict(response)
        if verdict is None:
            return JudgeVerdict(
                sensitive=True,
                reason=f"LLM returned unparseable response — failing closed",
                used_llm=True,
            )

        return JudgeVerdict(
            sensitive=verdict.get("sensitive", True),
            reason=verdict.get("reason", ""),
            used_llm=True,
        )

    except Exception as e:
        logger.error(f"guardrails-judge: LLM call failed: {e} — failing closed")
        return JudgeVerdict(
            sensitive=True,
            reason=f"LLM call failed: {e} — failing closed",
            used_llm=True,
        )


def _call_llm(llm, prompt: str) -> Optional[str]:
    """Call the LLM via the PluginLlm facade. Returns response text or None."""
    # Try chat() first (returns string or dict with 'content' key)
    try:
        result = llm.chat([
            {"role": "system", "content": "You are a security classifier. Respond only with JSON."},
            {"role": "user", "content": prompt},
        ])
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return result.get("content") or result.get("text")
        return str(result) if result else None
    except (AttributeError, TypeError):
        pass

    # Fall back to complete()
    try:
        result = llm.complete(prompt)
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return result.get("content") or result.get("text")
        return str(result) if result else None
    except Exception as e:
        logger.error(f"guardrails-judge: both chat() and complete() failed: {e}")
        return None


def _parse_verdict(response: str) -> Optional[dict]:
    """Parse the LLM's JSON response. Tolerates markdown fences and extra text."""
    text = response.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last fence lines
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from the response
    import re
    json_match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    return None