"""Tests for guardrails.store — SQLite audit log."""

import tempfile
import pytest
from pathlib import Path
from guardrails.store import AuditStore
from guardrails.detectors import scan, Finding, Severity


class TestAuditStore:
    @pytest.fixture
    def store(self, tmp_path):
        s = AuditStore(tmp_path / "test_guardrails.db")
        s.connect()
        yield s
        s.close()

    def test_connect_creates_db(self, tmp_path):
        s = AuditStore(tmp_path / "audit.db")
        s.connect()
        assert (tmp_path / "audit.db").exists()
        s.close()

    def test_log_blocked(self, store):
        findings = scan("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        row_id = store.log(
            tool_name="write_file",
            action="blocked",
            severity="high",
            findings=findings,
            message="PII detected",
            session_id="sess-123",
            task_id="task-456",
        )
        assert row_id > 0

    def test_log_and_retrieve(self, store):
        store.log(tool_name="terminal", action="blocked", severity="high",
                  findings=scan("sk-abcdefghijklmnopqrstuvwxyz1234567890"),
                  message="secret in command")
        entries = store.get_recent(limit=10)
        assert len(entries) == 1
        assert entries[0]["tool_name"] == "terminal"
        assert entries[0]["action"] == "blocked"

    def test_get_recent_with_filter(self, store):
        store.log(tool_name="write_file", action="blocked", severity="high",
                  findings=[], message="test1")
        store.log(tool_name="write_file", action="allowed", severity="info",
                  findings=[], message="test2")
        blocked = store.get_recent(limit=10, action_filter="blocked")
        assert len(blocked) == 1
        assert blocked[0]["action"] == "blocked"

    def test_get_stats(self, store):
        store.log(tool_name="write_file", action="blocked", severity="high",
                  findings=[], message="")
        store.log(tool_name="write_file", action="allowed", severity="info",
                  findings=[], message="")
        stats = store.get_stats()
        assert stats["total_blocked"] >= 1
        assert stats["total_allowed"] >= 1

    def test_get_blocked_count(self, store):
        store.log(tool_name="write_file", action="blocked", severity="high",
                  findings=[], message="")
        store.log(tool_name="terminal", action="blocked", severity="high",
                  findings=[], message="")
        assert store.get_blocked_count() == 2

    def test_clear(self, store):
        store.log(tool_name="write_file", action="blocked", severity="high",
                  findings=[], message="")
        deleted = store.clear()
        assert deleted >= 1
        assert store.get_recent() == []
        assert store.get_blocked_count() == 0

    def test_findings_serialized(self, store):
        findings = scan("sk-abcdefghijklmnopqrstuvwxyz1234567890")
        store.log(tool_name="write_file", action="blocked", severity="high",
                  findings=findings, message="test")
        entries = store.get_recent(limit=1)
        import json
        parsed = json.loads(entries[0]["findings_json"])
        assert len(parsed) >= 1
        assert "kind" in parsed[0]
        assert "masked_value" not in parsed[0]  # field is "value" in serialization
        assert "value" in parsed[0]

    def test_thread_safe(self, store):
        import threading
        results = []
        def _write():
            try:
                store.log(tool_name="write_file", action="blocked", severity="high",
                          findings=[], message="thread")
                results.append(True)
            except Exception:
                results.append(False)
        threads = [threading.Thread(target=_write) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(results)
        assert store.get_blocked_count() == 10

    def test_close_is_idempotent(self, store):
        store.close()
        store.close()  # should not raise

    def test_operations_after_close(self, store):
        store.close()
        assert store.get_recent() == []
        assert store.get_stats() == {}
        assert store.get_blocked_count() == 0