"""Tests for bridge-call indicators and the CLI session, on scenario fixtures.

Fixtures are cut from real captures (macOS 26.2, private data enabled):
  A  objc_scenario_a*.ndjson       minimal NSAlert, Script Editor (run twice) and osascript
  B  objc_scenario_b.ndjson        fake "Microsoft Word" credential applet; the typed
                                   test passwords are replaced by tstp1 / tstp2
  C  objc_scenario_c.ndjson        telemetry test script, download failed
     objc_scenario_c_download.ndjson  same script, download succeeded, plus a run that
                                   hit a failed class lookup (odSession)
"""

import json
import os

import pytest

from aemonitor import cli
from aemonitor.cli import OutputSession, _iter_ndjson_from_file
from aemonitor.indicators import SPECS, IndicatorEngine, hex_needle, hex_needles

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SECRETS = ("tstp1", "tstp2")
SECRET_HEX = tuple(s.encode("utf-16le").hex() for s in SECRETS)


def run(name, **options):
    """Run a fixture through an OutputSession; returns (lines, findings)."""
    options.setdefault("use_color", False)
    session = OutputSession(options.pop("style", "syslog"), indicators=True, **options)
    lines = []
    for entry in _iter_ndjson_from_file(os.path.join(FIXTURES, name)):
        lines += session.process(entry)
    lines += session.finish()
    findings = session.engine.findings() if session.engine is not None else []
    return lines, {f.name for f in findings}


@pytest.fixture(scope="module")
def scenario_a():
    return run("objc_scenario_a.ndjson")[1] | run("objc_scenario_a_osascript.ndjson")[1]


@pytest.fixture(scope="module")
def scenario_b():
    return run("objc_scenario_b.ndjson")[1]


@pytest.fixture(scope="module")
def scenario_c():
    return run("objc_scenario_c.ndjson")[1] | run("objc_scenario_c_download.ndjson")[1]


class TestScenarioIndicators:
    def test_a_only_alert_and_headless_to_gui(self, scenario_a):
        assert scenario_a == {"objc.ui.alert", "objc.ui.headless_to_gui"}

    def test_b(self, scenario_b):
        assert {
            "objc.cred.prompt_with_input",
            "objc.cred.reprompt_loop",
            "objc.cred.cleartext_leak",
            "objc.cred.saved_to_disk",
            "objc.lure.app_icon",
        } <= scenario_b

    def test_c(self, scenario_c):
        assert {
            "objc.recon.region",
            "objc.net.session",
            "objc.file.stage",
            "objc.cred.secure_field",
            "objc.cred.prompt_with_input",
            "objc.cred.window_raised",
            "objc.cred.od_verify",
            "objc.cred.reprompt_loop",
            "objc.cred.verify_result",
            "objc.net.url",
            "objc.bridge.failed_lookup",
        } <= scenario_c

    def test_file_stage_needs_the_download(self):
        assert "objc.file.stage" not in run("objc_scenario_c.ndjson")[1]
        assert "objc.file.stage" in run("objc_scenario_c_download.ndjson")[1]

    def test_c_has_no_cleartext_leak(self, scenario_c):
        # The secure field's value is passed on as an object, never as text
        assert "objc.cred.cleartext_leak" not in scenario_c

    def test_findings_name_supporting_return_ids(self):
        session = OutputSession("ndjson", use_color=False, indicators=True)
        for entry in _iter_ndjson_from_file(os.path.join(FIXTURES, "objc_scenario_c.ndjson")):
            session.process(entry)
        verify = [f for f in session.engine.findings() if f.name == "objc.cred.verify_result"][0]
        assert verify.return_ids == [-13458]
        assert verify.detail == "false"

    def test_indicators_printed_inline_and_summarized(self):
        lines, _ = run("objc_scenario_a_osascript.ndjson")
        assert any("indicator: objc.ui.alert" in line for line in lines)
        summary = lines[lines.index("Indicators (2):") + 1 :]
        assert any(line.strip().startswith("objc.ui.headless_to_gui") for line in summary)


def call(sel, receiver="NSWorkspace", kind="class", args=(), rid=1):
    return {
        "processID": 1,
        "appleEvent": {
            "objc": {
                "return_id": rid,
                "selector": sel,
                "receiver_kind": kind,
                "receiver": receiver,
                "args": list(args),
            }
        },
    }


def text(s):
    return {"type": "text", "value": s, "length": len(s), "truncated": False}


class TestUnseenIndicators:
    def test_post(self):
        e = IndicatorEngine()
        e.feed(call("setHTTPMethod_", "0x1", "instance", [text("GET")]))
        assert not e.findings()
        e.feed(call("setHTTPMethod_", "0x1", "instance", [text("POST")]))
        assert [f.name for f in e.findings()] == ["objc.net.post"]

    def test_task(self):
        e = IndicatorEngine()
        e.feed(call("launchedTaskWith", "NSTask"))
        assert "objc.exec.task" in {f.name for f in e.findings()}

    def test_workspace_open(self):
        e = IndicatorEngine()
        e.feed(call("openURL_", "NSWorkspace"))
        assert "objc.exec.task" in {f.name for f in e.findings()}

    def test_fires_once_per_process(self):
        e = IndicatorEngine()
        e.feed(call("launchedTaskWith", "NSTask", rid=1))
        e.feed(call("launchedTaskWith", "NSTask", rid=2))
        assert len(e.findings()) == 1


class TestNeedles:
    def test_hex_needle(self):
        assert hex_needle("verifyPassword") == "760065007200690066007900500061007300730077006f0072006400"
        assert hex_needle("NSURLSession") == "4e005300550052004c00530065007300730069006f006e00"

    def test_needles_cover_spec_prefixes(self):
        needles = hex_needles()
        assert ("objc.cred.secure_field", "NSSecureTextFiel", hex_needle("NSSecureTextFiel")) in needles
        assert all(name in SPECS for name, _, _ in needles)

    def test_needle_found_in_raw_message(self):
        raw = open(os.path.join(FIXTURES, "objc_scenario_c.ndjson")).read()
        assert hex_needle("verifyPassword_e") in raw
        assert hex_needle("NSSecureTextFiel") in raw


class TestLoggedAsIs:
    def test_b_typed_text_is_shown(self):
        lines, _ = run("objc_scenario_b.ndjson", style="ndjson", objc_results=True)
        out = "\n".join(lines)
        assert all(s in out for s in SECRETS + SECRET_HEX)
        assert "<redacted" not in out

    def test_dscl_command_is_shown(self):
        lines, _ = run("objc_scenario_b.ndjson")
        assert any("dscl . -authonly $(whoami) " in line and "tstp" in line for line in lines)


class TestOutput:
    def test_one_line_per_call_without_warnings(self, caplog):
        lines, _ = run("objc_scenario_c.ndjson")
        calls = [line for line in lines if " objc: " in line and " --> " not in line]
        assert len(calls) == 117
        assert "NOT IMPLEMENTED" not in caplog.text

    def test_results_only_with_flag(self):
        without, _ = run("objc_scenario_a.ndjson")
        with_results, _ = run("objc_scenario_a.ndjson", objc_results=True)
        assert not any("objc: --> " in line for line in without)
        modal = [line for line in with_results if "objc: --> 100" in line]
        assert sorted(line[-4:] for line in modal) == ["1000", "1001"]

    def test_no_objc_drops_bridge_calls(self):
        lines, _ = run("objc_scenario_c.ndjson", objc=False)
        assert not any(" objc: " in line for line in lines)

    def test_ndjson_keeps_raw_decoded_and_thread(self):
        lines, _ = run("objc_scenario_c.ndjson", style="ndjson")
        records = [json.loads(line) for line in lines if line.startswith("{")]
        objc = [r for r in records if "objc" in r.get("appleEvent", {})]
        assert objc
        first = objc[0]
        assert first["threadID"]
        assert first["appleEvent"]["objc"]["raw"].startswith("{ascr,psbr")
        assert first["appleEvent"]["objc"]["selector"] == "isMainThread"
        findings = [r for r in records if "finding" in r]
        assert {"indicator", "return_ids", "processID"} <= set(findings[0]["finding"])


class TestPredicate:
    def test_base_has_bridge_calls(self):
        assert 'eventMessage contains "cloneForCompatability(src={ascr,psbr"' in cli.BASE_PREDICATE
        assert "errn type long" not in cli.BASE_PREDICATE

    def test_results_clauses(self):
        p = cli._build_predicate(None, objc_results=True)
        assert 'eventMessage contains "for keyword errn type long"' in p
        assert 'eventMessage contains "(----) as **** ="' in p
        assert 'eventMessage contains "AECreateAppleEvent("' in p

    def test_no_objc(self):
        p = cli._build_predicate(None, objc=False, objc_results=True)
        assert "ascr,psbr" not in p
        assert "errn" not in p
        assert 'eventMessage contains[c] "event={"' in p

    def test_stream_captures_results_for_indicators(self, monkeypatch):
        seen = {}

        def fake_iter(predicate):
            seen["predicate"] = predicate
            return (e for e in [])

        monkeypatch.setattr(cli, "iter_live_entries", fake_iter)
        cli._stream_or_parse(output_format="ndjson", backend="native", indicators=True)
        assert "errn type long" in seen["predicate"]


class TestProcessIdentity:
    def test_reused_pid_gets_its_own_findings(self):
        # The same pid reused by an unrelated program fires its own indicators;
        # each indicator still fires only once per process
        session = OutputSession("ndjson", indicators=True, use_color=False)
        entries = list(_iter_ndjson_from_file(os.path.join(FIXTURES, "objc_scenario_a_osascript.ndjson")))
        for image in ("/usr/bin/osascript", "/tmp/other", "/tmp/other"):
            for e in entries:
                session.process({**e, "processImagePath": image})
        names = [f.name for f in session.engine.findings()]
        assert names.count("objc.ui.alert") == 2
        assert {f.process for f in session.engine.findings()} == {"osascript", "other"}
