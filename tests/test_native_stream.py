"""Tests for the in-process LoggingSupport backend."""

import builtins
import json
from datetime import datetime

import pytest

from aemonitor import native_stream
from aemonitor.cli import _process_and_output
from aemonitor.native_stream import NativeStreamUnavailable, proxy_to_entry


class FakeDate:
    def __init__(self, ts: float):
        self.ts = ts

    def timeIntervalSince1970(self):
        return self.ts


class FakeProxy:
    """Mimics the OSLogEventProxy accessors used by proxy_to_entry."""

    def __init__(self, **overrides):
        self.values = {
            "date": FakeDate(1762900000.123456),
            "logType": 2,
            "composedMessage": "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082} reply=0xNULL-impl sendMode=1043 timeout=7200",
            "formatString": "%{public}*csendToSelf(), event=%{public}s",
            "subsystem": "com.apple.appleevents",
            "category": "main",
            "processIdentifier": 4242,
            "processImagePath": "/usr/bin/osascript",
            "processImageUUID": "99CBF19A-1ED1-3EA5-9986-16148A3D9E2D",
            "senderImagePath": "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE",
            "userIdentifier": 501,
            "threadIdentifier": 35035483,
            "activityIdentifier": 0,
            "parentActivityIdentifier": 0,
            "traceIdentifier": 654248210705154564,
        }
        self.values.update(overrides)

    def __getattr__(self, name):
        if name in self.__dict__.get("values", {}):
            return lambda: self.values[name]
        raise AttributeError(name)


class TestProxyToEntry:
    def test_maps_to_log_ndjson_keys(self):
        entry = proxy_to_entry(FakeProxy())
        assert entry["eventMessage"].startswith("sendToSelf()")
        assert entry["processImagePath"] == "/usr/bin/osascript"
        assert entry["processID"] == 4242
        assert entry["threadID"] == 35035483
        assert entry["userID"] == 501
        assert entry["messageType"] == "Debug"
        assert entry["subsystem"] == "com.apple.appleevents"
        json.dumps(entry)  # must be serializable for --style ndjson

    def test_timestamp_matches_log_format(self):
        entry = proxy_to_entry(FakeProxy())
        # e.g. 2025-11-12 09:26:40.123456+1100, same as `log --style ndjson`
        parsed = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S.%f%z")
        assert parsed.timestamp() == pytest.approx(1762900000.123456)

    def test_missing_values(self):
        entry = proxy_to_entry(
            FakeProxy(date=None, composedMessage=None, processImagePath=None, logType=99)
        )
        assert entry["timestamp"] == ""
        assert entry["eventMessage"] == ""
        assert entry["processImagePath"] == ""
        assert entry["messageType"] == "99"

    def test_enriches_like_log_backend(self):
        out = _process_and_output(proxy_to_entry(FakeProxy()), "ndjson")
        assert out is not None
        parsed = json.loads(out)
        assert "do shell script" in parsed["appleEvent"]["event"]["applescript"]


def test_missing_pyobjc_raises_unavailable(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("objc", "Foundation"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(NativeStreamUnavailable, match="aemonitor\\[native\\]"):
        native_stream.iter_live_entries("subsystem == 'x'")
