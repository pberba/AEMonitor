"""Tests for the aemonitor CLI."""

import json
import os
import tempfile

import pytest

from aemonitor import cli
from aemonitor.cli import (
    _build_predicate,
    _format_decompiled_message,
    _format_syslog_line,
    _iter_ndjson_from_file,
    _process_and_output,
    BASE_PREDICATE,
)
from aemonitor.native_stream import NativeDependenciesMissing, NativeStreamUnavailable


class TestBuildPredicate:
    def test_base_predicate_only(self):
        assert _build_predicate(None) == BASE_PREDICATE

    def test_extra_predicate_combined(self):
        result = _build_predicate('process == "Finder"')
        assert BASE_PREDICATE in result
        assert 'process == "Finder"' in result
        assert " AND " in result

    @pytest.mark.parametrize("prefix", cli.CLONE_SRC_PREFIXES)
    def test_admits_every_clone_encoding_that_decodes(self, prefix):
        # Only quoted sources used to pass, so utxt/list/record/compiled-script clones
        # never reached extract_clone_src outside .ndjson files
        assert "eventMessage contains " + json.dumps(f"cloneForCompatability(src={prefix}") in BASE_PREDICATE


class TestNdjsonPath:
    @pytest.mark.parametrize("path", ["a.ndjson", "a.jsonl", "A.JSONL"])
    def test_json_lines_files(self, path):
        assert cli.is_ndjson_path(path)

    def test_archive(self):
        assert not cli.is_ndjson_path("capture.logarchive")


class TestProcessAndOutput:
    """Test _process_and_output with sample unified log entries."""

    def test_ndjson_output(self):
        # Use a known-good event from test_unified_logs (syso,exec killall Terminal)
        entry = {
            "eventMessage": "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082} reply=0xNULL-impl sendMode=1043 timeout=7200",
            "processImagePath": "/usr/bin/osascript",
            "timestamp": "2024-01-01 12:00:00",
        }
        out = _process_and_output(entry, "ndjson")
        assert out is not None
        parsed = json.loads(out)
        assert "appleEvent" in parsed
        assert "event" in parsed["appleEvent"]
        assert "applescript" in parsed["appleEvent"]["event"]
        assert "raw" in parsed["appleEvent"]["event"]

    def test_syslog_output(self):
        entry = {
            "eventMessage": "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl} returnID=-27082} reply=0xNULL-impl",
            "processImagePath": "/usr/bin/osascript",
            "timestamp": "2024-01-01 12:00:00",
            "process": "osascript",
            "subsystem": "com.apple.appleevents",
        }
        out = _process_and_output(entry, "syslog")
        assert out is not None
        assert "do shell script" in out or "osascript" in out
        assert "event:" in out

    def test_skips_empty_extract(self):
        entry = {"eventMessage": "some random log with no event= or reply="}
        out = _process_and_output(entry, "ndjson")
        assert out is None

    def test_clone_syslog_output(self):
        """Clone output is properly escaped (JSON-style with quotes)."""
        entry = {
            "eventMessage": "cloneForCompatability(src=\"test -d '/Applications/Ledger Live.app'\" dst=0x16ef41dbc",
            "processImagePath": "/usr/bin/osascript",
            "timestamp": "2026-02-12 23:27:05.235518+0000",
            "processID": 1819,
        }
        out = _process_and_output(entry, "syslog", use_color=False)
        assert out is not None
        # Escaped string format: clone: "test -d '/Applications/Ledger Live.app'"
        assert "clone:" in out
        assert "test -d" in out
        assert "Ledger Live.app" in out

    def test_clone_syslog_escapes_special_chars(self):
        """Clone output escapes special chars (newlines, quotes) via JSON encoding.
        Clone must be > 16 chars to be printed; <= 16 chars returns None."""
        # Reset _last_clone to avoid dedup from other tests
        _process_and_output._last_clone = None

        # > 16 chars: should be printed and escaped
        entry_long = {
            "eventMessage": 'cloneForCompatability(src="line1\nline2 with more text" dst=0x123)',
            "processImagePath": "/usr/bin/osascript",
            "timestamp": "2026-02-12 12:00:00",
            "processID": 123,
        }
        out = _process_and_output(entry_long, "syslog", use_color=False)
        assert out is not None
        assert "clone:" in out
        assert "line1" in out
        assert "line2" in out
        assert "\\n" in out  # escaped newline

        # <= 16 chars: should return None (not printed)
        _process_and_output._last_clone = None
        entry_short = {
            "eventMessage": 'cloneForCompatability(src="short" dst=0x123)',
            "processImagePath": "/usr/bin/osascript",
            "timestamp": "2026-02-12 12:00:00",
            "processID": 123,
        }
        out_short = _process_and_output(entry_short, "syslog", use_color=False)
        assert out_short is None

    def test_clone_ndjson_output(self):
        entry = {
            "eventMessage": 'cloneForCompatability(src="hello" dst=0x123)',
            "timestamp": "2026-02-12 12:00:00",
        }
        out = _process_and_output(entry, "ndjson")
        assert out is not None
        parsed = json.loads(out)
        assert parsed["appleEvent"]["clone"] == "hello"

    def test_skips_missing_event_message(self):
        entry = {"process": "foo"}
        out = _process_and_output(entry, "ndjson")
        assert out is None


class TestFormatSyslogLine:
    def test_format_with_decompiled(self):
        enriched = {
            "timestamp": "2024-01-01 12:00:00.000000-0800",
            "threadID": "0x1234",
            "logType": "Default",
            "activityIdentifier": "0x0",
            "processID": 12345,
            "timeToLive": 0,
            "processImagePath": "/usr/bin/osascript",
            "subsystem": "com.apple.appleevents",
            "appleEvent": {
                "event": {
                    "applescript": 'tell application "Finder" to get name of front window'
                },
            },
        }
        line = _format_syslog_line(enriched, use_color=False)
        assert "2024-01-01" in line
        assert "osascript" in line
        assert "tell application" in line
        assert "Finder" in line

    def test_format_decompiled_message_event_and_reply(self):
        """When both event and reply exist, only reply is printed."""
        enriched = {
            "appleEvent": {
                "event": {"applescript": "tell Finder to open file"},
                "reply": {"applescript": "result: /path/to/file"},
            }
        }
        msg = _format_decompiled_message(enriched, use_color=False)
        assert "reply: result: /path/to/file" in msg
        assert "event: tell Finder to open file" not in msg


class TestIterNdjsonFromFile:
    def test_reads_ndjson_line_by_line(self):
        sample = {
            "eventMessage": "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(8/$6b0069006c006c)} attr:{} returnID=-1} reply=0xNULL-impl",
            "processImagePath": "/usr/bin/osascript",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f:
            f.write(json.dumps(sample) + "\n")
            f.write(json.dumps({"eventMessage": "other", "x": 1}) + "\n")
            path = f.name
        try:
            entries = list(_iter_ndjson_from_file(path))
            assert len(entries) == 2
            assert entries[0]["eventMessage"] == sample["eventMessage"]
            assert entries[1]["eventMessage"] == "other"
        finally:
            os.unlink(path)

    def test_skips_empty_lines_and_finished(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ndjson", delete=False) as f:
            f.write('{"eventMessage":"foo"}\n')
            f.write("\n")
            f.write('{"finished": true}\n')
            f.write('{"eventMessage":"bar"}\n')
            path = f.name
        try:
            entries = list(_iter_ndjson_from_file(path))
            assert len(entries) == 2
            assert entries[0]["eventMessage"] == "foo"
            assert entries[1]["eventMessage"] == "bar"
        finally:
            os.unlink(path)


class TestStreamBackendSelection:
    """`stream --backend auto` uses native when available, otherwise falls back to `log stream`."""

    class LogStreamCalled(Exception):
        pass

    @pytest.fixture
    def log_stream(self, monkeypatch):
        def fake_run_log_stream(predicate):
            raise self.LogStreamCalled()

        monkeypatch.setattr(cli, "_run_log_stream", fake_run_log_stream)

    def _unavailable(self, monkeypatch, exc):
        def fake_iter_live_entries(predicate):
            raise exc

        monkeypatch.setattr(cli, "iter_live_entries", fake_iter_live_entries)

    def test_auto_uses_native_when_available(self, monkeypatch, log_stream):
        monkeypatch.setattr(cli, "iter_live_entries", lambda predicate: (e for e in []))
        assert cli._stream_or_parse(output_format="ndjson", backend="auto") == 0

    def test_auto_falls_back_silently_without_pyobjc(self, monkeypatch, log_stream, capsys):
        self._unavailable(monkeypatch, NativeDependenciesMissing("no pyobjc"))
        with pytest.raises(self.LogStreamCalled):
            cli._stream_or_parse(output_format="ndjson", backend="auto")
        assert "falling back" not in capsys.readouterr().err

    def test_auto_warns_when_native_installed_but_broken(self, monkeypatch, log_stream, capsys):
        self._unavailable(monkeypatch, NativeStreamUnavailable("OSLogEventLiveStream not found"))
        with pytest.raises(self.LogStreamCalled):
            cli._stream_or_parse(output_format="ndjson", backend="auto")
        assert "falling back to log stream" in capsys.readouterr().err

    def test_native_errors_instead_of_falling_back(self, monkeypatch, log_stream, capsys):
        self._unavailable(monkeypatch, NativeDependenciesMissing("requires PyObjC"))
        assert cli._stream_or_parse(output_format="ndjson", backend="native") == 1
        assert "requires PyObjC" in capsys.readouterr().err

    def test_log_skips_native(self, monkeypatch, log_stream):
        monkeypatch.setattr(cli, "iter_live_entries", lambda predicate: pytest.fail("native used"))
        with pytest.raises(self.LogStreamCalled):
            cli._stream_or_parse(output_format="ndjson", backend="log")
