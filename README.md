# Hermes Guardrails — Security Plugin

PII detection, code safety scanning, and audit logging for Hermes Agent.

## Why

Prevents sensitive data (phone numbers, SSH usernames, hostnames, API keys, tokens)
from being written to files, committed to git repos, or stored in memory — and logs
every blocked attempt for audit.

## What it does

- Pattern-based PII detection (regex, <1ms, no LLM needed)
- LLM judge for ambiguous cases (uses ctx.llm, fails CLOSED)
- pre_tool_call hook blocks writes/commands before execution
- transform_tool_result hook redacts secrets from tool output
- post_tool_call hook logs all tool activity to audit log
- 4 agent tools: guardrails_status, guardrails_rules, guardrails_audit, guardrails_scan

## Install

1. Copy plugin to Hermes plugins dir
2. Add to plugins.enabled in config
3. Restart Hermes

See README.md for full details.