# Hermes Guardrails — Security Plugin

PII detection, code safety scanning, and audit logging for Hermes Agent.
Blocks sensitive data before it reaches disk, git, or memory.

## Why

Prevents sensitive data (phone numbers, remote account names, hostnames, API
keys, tokens) from being written to files, committed to git repos, or stored
in memory — and logs every blocked attempt for audit.

Built after a real incident: personal environment data leaked into a public
repo through test fixtures. Guardrails exists to make that class of leak
impossible.

## What it does

- **Pattern-based PII detection** — 10 regex detectors, <1ms, no LLM needed:
  phone, api_key, password, ssh_user, hostname, email, ip_address, port,
  hex_token, sensitive_path
- **LLM judge for ambiguous cases** — uses the host model, fails CLOSED
  (blocks if the judge is unavailable)
- **3 lifecycle hooks:**
  - `pre_tool_call` — blocks writes/commands before execution
  - `post_tool_call` — logs all tool activity to the audit DB
  - `transform_tool_result` — redacts secrets from tool output
- **4 agent tools:** `guardrails_status`, `guardrails_rules`,
  `guardrails_audit`, `guardrails_scan`
- **WebUI panel** — Memory → Guardrails: audit log, blocked attempts, stats

## Install

```bash
mkdir -p ~/.hermes/plugins/guardrails
cp -r /root/hermes-guardrails/guardrails/* ~/.hermes/plugins/guardrails/
```

Enable in `~/.hermes/config.yaml` (proper YAML list — `hermes config set`
stores JSON-looking values as strings):

```yaml
plugins:
  enabled:
    - tool_forge
    - guardrails
```

```bash
sudo systemctl restart hermes-webui
# and, if your API session is served by the gateway:
systemctl restart hermes-gateway
```

## Config

| Key | Default | Meaning |
|---|---|---|
| `guardrails.enabled` | `true` | Master switch |
| `guardrails.fail_closed` | `true` | Block if LLM judge unavailable |
| `guardrails.scan_tools` | `[write_file, patch, terminal, memory]` | Tools scanned pre-execution |
| `guardrails.redact_tools` | `[terminal, read_file]` | Tools with output redaction |
| `guardrails.public_repos` | `[]` | Repos known to be public — medium findings BLOCK there |

```yaml
guardrails:
  enabled: true
  public_repos:
    - HermesZum/hermes-cognitive-memory
    - HermesZum/hermes-tool-forge
    - HermesZum/hermes-guardrails
```

## Decision logic

| Severity | Context | Action |
|---|---|---|
| `high` (secrets, tokens) | anywhere | **BLOCK** |
| `medium` (phone, hostname, email, ssh_user) | inside a configured public repo | **BLOCK** |
| `medium` | anywhere else | **WARN** (write allowed, warning injected) |
| `low` (ports, sensitive paths) | anywhere | **INFO** (log only) |

The public-repo match uses the local directory basename (`hermes-guardrails`
matches `/root/hermes-guardrails/...`) — not just the full `org/repo` string —
with exact path-segment matching to avoid false positives on
`/root/myrepo-backup/`.

The `ssh_user` detector requires the captured word to look like a real
account name (contains a digit/underscore, or a known common username) —
prose like "account names" or "login" does not trigger.

## Verified test results (2026-08-11)

**guardrails_scan (agent tool):** 5 findings on sample content — phone,
email, hostname, IP, ssh_user — with severities and masked context snippets.

**pre_tool_call — WARN path:** writing a file with phone + email + hostname +
ssh_user to `/tmp/` produced a warning, the write allowed, logged to audit.

**pre_tool_call — BLOCK path (high):** writing an API key (`sk-proj-...`)
anywhere was blocked entirely:

```
GUARDRAILS: Blocked write_file — PII/sensitive data detected:
  [high] api_key: sk-p************************************
Use fictional placeholders instead. Never commit real environment data.
```

**pre_tool_call — BLOCK path (medium in public repo):** writing a file with
phone + email + hostname into `/root/hermes-guardrails/` (configured public)
was blocked; the file was NOT created. The block message lists each finding
with its masked value and context snippet.

**Dogfooding note:** this README was initially blocked by the plugin — the
documented test examples contained patterns the detectors match, and since
the file lives inside a configured public repo, the write was BLOCKED until
the examples were sanitized to placeholders. The plugin protects its own
repository. It also caught an over-broad `ssh_user` regex during that same
write (prose "account names" triggered it) — fixed with a username-likeness
filter and two regression tests.

**post_tool_call:** every scanned tool logged to the audit DB.

**guardrails_audit:** full trail viewable — 80+ entries with timestamp, tool,
action, severity, masked findings, and the exact message sent to the LLM.

## Agent tools

| Tool | Purpose |
|---|---|
| `guardrails_status` | Detection stats, blocked counts, config summary |
| `guardrails_rules` | List / enable / disable scan rules per tool |
| `guardrails_audit` | View the blocked-attempt log |
| `guardrails_scan` | Manually scan content for PII (use before git commit) |

## Storage

SQLite audit log at `~/.hermes/guardrails/guardrails.db`:

- `audit_log` — every scan decision (blocked/warned/allowed/scanned) with
  timestamp, tool, action, severity, masked findings JSON, message
- `stats` — aggregate counters: total_blocked, total_warned, total_scanned,
  total_allowed
- Thread-safe (RLock + WAL + busy_timeout), parameterized queries only

## Security model

- **Fails closed** — if the LLM judge is unavailable, ambiguous cases BLOCK
- **Masked findings only** — the audit log stores masked values, never raw PII
- **No Hermes internals in the WebUI** — the bridge loads `store.py` directly
  under a synthetic package name
- **Detectors are regex, deterministic, <1ms** — the LLM judge is only for
  ambiguous edge cases

## Tests

```bash
cd /root/hermes-guardrails
python3 -m pytest tests/ -q
```

113 tests: detectors (per-pattern + edge cases + false-positive regression),
rules (decision matrix), judge (fail-closed fallback), store (audit CRUD +
stats), plugin (hook wiring).

## Development

Project structure:

```
hermes-guardrails/
├── guardrails/
│   ├── __init__.py       # plugin entry — hooks + tools + config
│   ├── detectors.py      # 10 regex PII detectors
│   ├── rules.py          # decision engine (block/warn/allow)
│   ├── judge.py          # LLM judge, fail-closed
│   └── store.py          # SQLite audit log + stats
├── tests/
│   ├── test_detectors.py
│   ├── test_rules.py
│   ├── test_judge.py
│   ├── test_store.py
│   └── test_plugin.py
├── pyproject.toml
├── pytest.ini
├── LICENSE (MIT)
└── .gitignore
```
