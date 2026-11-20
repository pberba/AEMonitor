"""Tests for pairing bridge calls with their return values (aemonitor.objc_correlate)."""

import os

import pytest

from aemonitor.objc_correlate import (
    MAX_THREADS,
    BridgeTracker,
    class_base_name,
    selector_base_name,
)
from aemonitor.unified_logs import enrich_unified_log

from test_objc import (
    CLASS_OD_SESSION,
    CLASS_SECURE_FIELD_ALLOC,
    FAILED_LOOKUP,
    INSTANCE_STRING_VALUE,
    INSTANCE_VERIFY_PASSWORD,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

GPD = "OSErr AEGetParamDesc(const AppleEvent *, AEKeyword, DescType, AEDesc *)(----) as **** = "
ANCHOR = "AEGetParamDesc for keyword errn type long"
CREATE = "OSErr AECreateAppleEvent(AEEventClass, AEEventID, const AEAddressDesc *, AEReturnID, AETransactionID, AppleEvent *)({} target=NULL-impl transID=0"


def entry(message, tid=1, pid=100):
    return {"eventMessage": message, "processID": pid, "threadID": tid, "processImagePath": "/x/applet"}


class Feeder:
    """Feeds lines the way the CLI does: bridge calls enriched, the rest raw."""

    def __init__(self):
        self.tracker = BridgeTracker()

    def __call__(self, message, tid=1, pid=100):
        e = entry(message, tid, pid)
        if "ascr,psbr" in message and ("src={" in message or "event={" in message):
            return self.tracker.on_call(enrich_unified_log(e))
        return self.tracker.on_line(e)


def result_of(record):
    return record["appleEvent"]["objc_result"]


class TestResults:
    def test_scalar(self):
        f = Feeder()
        f(INSTANCE_STRING_VALUE)
        f(GPD + "[] err=0/noErr")  # argument echo: not the result
        f(ANCHOR)
        r = result_of(f(GPD + "1000 err=0/noErr"))
        assert r["return_id"] == 4313
        assert r["result"] == 1000
        assert r["applescript"] == "1000"

    def test_argument_echo_is_not_a_result(self):
        f = Feeder()
        f(INSTANCE_VERIFY_PASSWORD)
        echo = GPD + "[{form=ID  ,want=ocid,seld=optr(8/$00d754090b000000),from=NULL-impl},obj ] err=0/noErr"
        assert f(echo) is None

    def test_list_with_pointer(self):
        f = Feeder()
        f(INSTANCE_VERIFY_PASSWORD)
        f(ANCHOR)
        r = result_of(
            f(GPD + "[FALSE,{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$1002df0e0b000000)}] err=0/noErr")
        )
        assert r["result"] == [False, {"type": "object", "ptr": "0xb0edf0210"}]
        # the second object of an error:(reference) call is the NSError
        assert r["applescript"] == "{false, error1}"

    def test_void(self):
        f = Feeder()
        f(INSTANCE_STRING_VALUE)
        f(ANCHOR)
        r = result_of(f(GPD + "NULL-impl err=-1701/errAEDescNotFound"))
        assert r["void"] is True
        assert r["result"] is None

    def test_anchor_with_empty_stack_is_dropped(self):
        f = Feeder()
        f(ANCHOR)
        assert f(GPD + "1000 err=0/noErr") is None

    def test_threads_are_independent(self):
        f = Feeder()
        f(INSTANCE_STRING_VALUE, tid=1)
        f(ANCHOR, tid=2)
        assert f(GPD + "5 err=0/noErr", tid=2) is None
        f(ANCHOR, tid=1)
        assert result_of(f(GPD + "7 err=0/noErr", tid=1))["result"] == 7

    def test_nested_call(self):
        # A delegate handler fires inside runUntilDate_ and makes its own call
        f = Feeder()
        f(CLASS_OD_SESSION)  # outer, returnID 10552
        f(INSTANCE_STRING_VALUE)  # inner, returnID 4313
        f(ANCHOR)
        assert result_of(f(GPD + "1 err=0/noErr"))["return_id"] == 4313
        f(ANCHOR)
        assert result_of(f(GPD + "2 err=0/noErr"))["return_id"] == 10552

    def test_internal_event_results_are_not_call_results(self):
        # core,getd evaluating a callback argument inside the outer call
        f = Feeder()
        f(CLASS_OD_SESSION)
        f(CREATE.format("core,getd"))
        f(ANCHOR)
        assert f(GPD + "{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$c008360a0b000000)} err=0/noErr") is None
        f(ANCHOR)
        assert result_of(f(GPD + "NULL-impl err=-1701/errAEDescNotFound"))["return_id"] == 10552

    def test_shell_command_reply_is_not_a_call_result(self):
        f = Feeder()
        f(CREATE.format("syso,exec"))
        f(ANCHOR)
        assert f(GPD + '"" err=0/noErr') is None

    def test_coercion_after_object_result(self):
        f = Feeder()
        f(INSTANCE_STRING_VALUE)
        f(ANCHOR)
        f(GPD + "{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$a11140531f55138e)} err=0/noErr")
        f(CREATE.format("core,getd"))
        f(ANCHOR)
        r = result_of(f(GPD + "utxt(10/$680065006c006c006f00) err=0/noErr"))
        assert r["return_id"] == 4313
        assert r["coerced"]["value"] == "hello"
        assert r["applescript"] == 'as text --> "hello"'


class TestNames:
    def test_alloc_names_by_class(self):
        f = Feeder()
        f(CLASS_SECURE_FIELD_ALLOC)
        f(ANCHOR)
        r = result_of(f(GPD + "{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$801f730e0b000000)} err=0/noErr"))
        assert r["applescript"] == "secureTextFiel1"
        # The next call on that pointer uses the alias and knows its class
        rec = f(INSTANCE_STRING_VALUE)
        assert rec["appleEvent"]["objc"]["applescript"] == "secureTextFiel1's stringValue()"
        assert rec["appleEvent"]["objc"]["receiver_class"] == "NSSecureTextFiel"

    def test_unknown_pointer_gets_generic_alias(self):
        f = Feeder()
        rec = f(INSTANCE_STRING_VALUE)
        assert rec["appleEvent"]["objc"]["applescript"] == "obj1's stringValue()"

    def test_reused_pid_starts_fresh(self):
        # pid 7 exits and an unrelated program gets it: no names, and no "already
        # seen" returnIDs, carry over
        tracker = BridgeTracker()

        def call(message, image):
            e = {"eventMessage": message, "processID": 7, "threadID": 1, "processImagePath": image}
            return tracker.on_call(enrich_unified_log(e))

        assert call(INSTANCE_STRING_VALUE, "/x/first")["appleEvent"]["objc"]["applescript"].startswith("obj1")
        second = call(INSTANCE_VERIFY_PASSWORD, "/x/second")
        assert second["appleEvent"]["objc"]["applescript"].startswith("obj1")
        assert call(INSTANCE_STRING_VALUE, "/x/second") is not None  # its own returnID space

    def test_tracked_threads_are_bounded(self):
        f = Feeder()
        for tid in range(MAX_THREADS + 50):
            f(CREATE.format("core,getd"), tid=tid)
        assert len(f.tracker._stacks) == MAX_THREADS

    def test_already_paired_result_is_kept(self):
        # Re-reading an AEMonitor export: the anchor lines that paired it are gone
        rec = {**entry(GPD + "1000 err=0/noErr"), "appleEvent": {"objc_result": {"return_id": 4313}}}
        assert BridgeTracker().on_line(rec) is rec

    def test_aliases_are_per_process(self):
        f = Feeder()
        a = f(INSTANCE_STRING_VALUE, pid=1)
        b = f(INSTANCE_VERIFY_PASSWORD, pid=2)
        assert a["appleEvent"]["objc"]["applescript"].startswith("obj1")
        assert b["appleEvent"]["objc"]["applescript"].startswith("obj1")

    @pytest.mark.parametrize(
        "cls,name",
        [("NSAlert", "alert"), ("NSURLSession", "urlSession"), ("ODNode", "node"), ("NSSecureTextFiel", "secureTextFiel")],
    )
    def test_class_base_name(self, cls, name):
        assert class_base_name(cls) == name

    @pytest.mark.parametrize(
        "sel,name",
        [("recordWithRecord", "record"), ("window", "window"), ("objectForKey_", "object"), ("dataTaskWithRequ", "dataTask")],
    )
    def test_selector_base_name(self, sel, name):
        assert selector_base_name(sel) == name


class TestFailedLookup:
    CLONE = FAILED_LOOKUP.replace("sendToSelf(), event=", "cloneForCompatability(src=").split(" reply=")[0] + " dst=0x1"

    def test_reported_once(self):
        f = Feeder()
        first = f(self.CLONE)
        assert first is not None
        assert f(self.CLONE) is None  # the same call is logged twice
        r = result_of(f(FAILED_LOOKUP))
        assert r["error"] == "lookup failed"
        assert r["return_id"] == 26909

    def test_event_form_alone_is_a_call(self):
        f = Feeder()
        rec = f(FAILED_LOOKUP)
        assert rec["appleEvent"]["objc"]["lookup_failed"] is True


class TestTypedText:
    def test_text_field_read_is_flagged_and_kept_as_is(self):
        f = Feeder()
        f(CLASS_SECURE_FIELD_ALLOC)
        f(ANCHOR)
        f(GPD + "{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$801f730e0b000000)} err=0/noErr")
        f(INSTANCE_STRING_VALUE)
        f(ANCHOR)
        r = f(GPD + "utxt(10/$680065006c006c006f00) err=0/noErr")
        assert result_of(r)["secret_read"] is True
        assert result_of(r)["applescript"] == '"hello"'
        assert "680065006c006c006f00" in r["eventMessage"]


def _calls_and_results(path):
    from aemonitor.cli import _iter_ndjson_from_file

    f = BridgeTracker()
    calls, results = [], []
    for e in _iter_ndjson_from_file(path):
        m = e["eventMessage"]
        if "ascr,psbr" in m and ("src={" in m or "event={" in m):
            rec = f.on_call(enrich_unified_log(e))
            if rec and "objc" in rec["appleEvent"]:
                calls.append(rec["appleEvent"]["objc"])
        else:
            rec = f.on_line(e)
            if rec:
                results.append(rec["appleEvent"]["objc_result"])
    return calls, results


class TestScenarios:
    def test_scenario_a_run_modal_results(self):
        _, results = _calls_and_results(os.path.join(FIXTURES, "objc_scenario_a.ndjson"))
        modal = [r["result"] for r in results if r["selector"] == "runModal"]
        assert sorted(modal) == [1000, 1001]

    def test_scenario_c_verify_false_then_true(self):
        calls, results = _calls_and_results(os.path.join(FIXTURES, "objc_scenario_c.ndjson"))
        assert len(calls) == 117
        verify = [r["result"][0] for r in results if r["selector"].startswith("verifyPassword")]
        assert verify == [False, True]

    def test_scenario_c_trace(self):
        calls, _ = _calls_and_results(os.path.join(FIXTURES, "objc_scenario_c.ndjson"))
        trace = [c["applescript"] for c in calls]
        i = trace.index("secureTextFiel1's stringValue()")
        assert trace[i : i + 7] == [
            "secureTextFiel1's stringValue()",
            "ODSession's defaultSession()",
            'ODNode\'s nodeWithSession_…(session1, "/Local/Default", (reference))',
            "NSUserName()",
            'node1\'s recordWithRecord…("dsRecTypeStandar…", userName1, missing value, (reference))',
            "record1's verifyPassword_e…(stringValue1, (reference))",
            'secureTextFiel1\'s setStringValue:""',
        ]

    def test_scenario_c_callback_args_not_taken_as_result(self):
        _, results = _calls_and_results(os.path.join(FIXTURES, "objc_scenario_c.ndjson"))
        run_until = [r for r in results if r["selector"] == "runUntilDate_"]
        assert len(run_until) == 1 and run_until[0]["void"] is True
