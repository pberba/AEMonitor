"""Tests for AppleScriptObjC bridge-call decoding and rendering (aemonitor.objc)."""

import pytest

from aemonitor.objc import (
    decode_bridge_payload,
    decode_value,
    extract_clone_event,
    optr_to_ptr,
    parse_result_value,
    render_call,
    render_value,
)
from aemonitor.unified_logs import enrich_unified_log, extract_clone_src

# Verbatim eventMessage values (Script Editor, macOS 26.2)
CLASS_SECURE_FIELD_ALLOC = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(10/$61006c006c006f006300),----=[]} attr:{subj={form=usrp,want=prop,seld=utxt(34/$4e00530053006500630075007200650054006500780074004600690065006c00...),from=NULL-impl},csig=65536} returnID=-14976} dst=0x16af455a4"
CLASS_OD_SESSION = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(28/$640065006600610075006c007400530065007300730069006f006e00),----=[]} attr:{subj={form=usrp,want=prop,seld=utxt(18/$4f004400530065007300730069006f006e00),from=NULL-impl},csig=65536} returnID=10552} dst=0x16af455a4"
CLASS_OD_NODE = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(54/$6e006f00640065005700690074006800530065007300730069006f006e005f00...),----=[{form=ID  ,want=ocid,seld=optr(8/$e02bbf0e0b000000),from=NULL-impl},utxt(28/$2f004c006f00630061006c002f00440065006600610075006c007400),obj ]} attr:{subj={form=usrp,want=prop,seld=utxt(12/$4f0044004e006f0064006500),from=NULL-impl},csig=65536} returnID=-2074} dst=0x16af455a4"
FUNCTION_MAKE_RECT = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(20/$4e0053004d0061006b0065005200650063007400),----=[0,0,240,56]} attr:{subj=NULL-impl,csig=65536} returnID=3582} dst=0x16af455a4"
INSTANCE_SET_LEVEL = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(18/$7300650074004c006500760065006c005f00),----=[{form=usrp,want=prop,seld=utxt(38/$4e005300530074006100740075007300570069006e0064006f0077004c006500...),from=NULL-impl}]} attr:{subj={form=ID  ,want=ocid,seld=optr(8/$00a8740e0b000000),from=NULL-impl},me  ={form=ID  ,want=ocid,seld=optr(8/$00a8740e0b000000),from=NULL-impl},csig=65536} returnID=6047} dst=0x16af455a4"
INSTANCE_STRING_VALUE = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(22/$73007400720069006e006700560061006c0075006500),----=[]} attr:{subj={form=ID  ,want=ocid,seld=optr(8/$801f730e0b000000),from=NULL-impl},me  ={form=ID  ,want=ocid,seld=optr(8/$801f730e0b000000),from=NULL-impl},csig=65536} returnID=4313} dst=0x16af455a4"
INSTANCE_VERIFY_PASSWORD = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(42/$760065007200690066007900500061007300730077006f00720064005f006500...),----=[{form=ID  ,want=ocid,seld=optr(8/$00d754090b000000),from=NULL-impl},obj ]} attr:{subj={form=ID  ,want=ocid,seld=optr(8/$a097250a0b000000),from=NULL-impl},me  ={form=ID  ,want=ocid,seld=optr(8/$a097250a0b000000),from=NULL-impl},csig=65536} returnID=-13458} dst=0x16af455a4"
SCRIPT_PERFORM_SELECTOR = "cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(106/$70006500720066006f0072006d00530065006c006500630074006f0072004f00...),----=[utxt(16/$6d00610069006e0046006c006f007700),msng,true(0/$)]} attr:{subj=NULL-impl,me  ={want=ocid,form=ID  ,seld=optr(8/$a0d02aba0c000000),from=NULL-impl},csig=65536} returnID=25766} dst=0x16b74e"
SET_MESSAGE_TEXT = "cloneForCompatability(src={ascr,psbr target='psn '[osascript] {snam=utxt(30/$7300650074004d0065007300730061006700650054006500780074005f00),----=[utxt(10/$480065006c006c006f00)]} attr:{subj={form=ID  ,want=ocid,seld=optr(8/$c04d12bd08000000),from=NULL-impl},me  ={form=ID  ,want=ocid,seld=optr(8/$c04d12bd08000000),from=NULL-impl},csig=65536} returnID=1} dst=0x1"
FAILED_LOOKUP = "sendToSelf(), event={ascr,psbr target='psn '[Script Editor] {snam=utxt(28/$640065006600610075006c007400530065007300730069006f006e00),----=[]} attr:{subj={form=usrp,want=prop,seld=utxt(18/$6f006400530065007300730069006f006e00),from=NULL-impl},csig=65536} returnID=26909} reply=0xNULL-impl sendMode=1043 timeout=7200"


def call(message):
    return decode_bridge_payload(extract_clone_event(message))


class TestExtract:
    def test_balanced_payload(self):
        payload = extract_clone_event(INSTANCE_SET_LEVEL)
        assert payload.startswith("{ascr,psbr")
        assert payload.endswith("returnID=6047}")

    def test_not_a_clone(self):
        assert extract_clone_event("event={ascr,psbr }") is None


class TestReceivers:
    def test_class_complete(self):
        c = call(CLASS_OD_SESSION)
        assert c["receiver_kind"] == "class"
        assert c["receiver"] == "ODSession"
        assert c["receiver_truncated"] is False
        assert c["selector"] == "defaultSession"
        assert c["args"] == []
        assert c["return_id"] == 10552

    def test_class_truncated(self):
        c = call(CLASS_SECURE_FIELD_ALLOC)
        assert c["receiver"] == "NSSecureTextFiel"
        assert c["receiver_truncated"] is True
        assert render_call(c) == "NSSecureTextFiel…'s alloc()"

    def test_instance(self):
        c = call(INSTANCE_STRING_VALUE)
        assert c["receiver_kind"] == "instance"
        assert c["receiver"] == "0xb0e731f80"
        assert render_call(c, lambda p: "secureField") == "secureField's stringValue()"

    def test_function(self):
        c = call(FUNCTION_MAKE_RECT)
        assert c["receiver_kind"] == "function"
        assert render_call(c) == "NSMakeRect(0, 0, 240, 56)"

    def test_script_object(self):
        c = call(SCRIPT_PERFORM_SELECTOR)
        assert c["receiver_kind"] == "script"
        assert render_call(c) == 'my performSelectorO…("mainFlow", missing value, true)'


class TestSelectors:
    def test_complete_selector_is_interleaved(self):
        c = call(SET_MESSAGE_TEXT)
        assert c["selector"] == "setMessageText_"
        assert render_call(c, lambda p: "alert1") == 'alert1\'s setMessageText:"Hello"'

    def test_truncated_selector_is_never_completed(self):
        c = call(INSTANCE_VERIFY_PASSWORD)
        assert c["selector"] == "verifyPassword_e"
        assert c["selector_truncated"] is True
        assert c["truncated"] is True
        assert (
            render_call(c, lambda p: {"0xb0a2597a0": "record", "0xb0954d700": "pw"}[p])
            == "record's verifyPassword_e…(pw, (reference))"
        )

    def test_truncated_selector_with_mixed_args(self):
        c = call(CLASS_OD_NODE)
        assert render_call(c, lambda p: "session") == (
            'ODNode\'s nodeWithSession_…(session, "/Local/Default", (reference))'
        )

    def test_enum_argument(self):
        c = call(INSTANCE_SET_LEVEL)
        assert c["args"] == [{"type": "constant", "name": "NSStatusWindowLe", "truncated": True}]
        assert render_call(c, lambda p: "window") == "window's setLevel:NSStatusWindowLe…"


class TestValues:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("utxt(10/$680065006c006c006f00)", {"type": "text", "value": "hello", "length": 5, "truncated": False}),
            ("true(0/$)", True),
            ("fals(0/$)", False),
            ("TRUE", True),
            ("FALSE", False),
            ("msng", {"type": "missing"}),
            ("1000", 1000),
            ("-1", -1),
            ("0.1", 0.1),
            ("NULL-impl", None),
            ("[[0,0],[240,56]]", [[0, 0], [240, 56]]),
            ("[15]", [15]),
            ("[TRUE,msng]", [True, {"type": "missing"}]),
        ],
    )
    def test_scalars_and_lists(self, raw, expected):
        assert parse_result_value(raw) == expected

    def test_truncated_text(self):
        v = parse_result_value("utxt(42/$760065007200690066007900500061007300730077006f00720064005f006500...)")
        assert v["value"] == "verifyPassword_e"
        assert v["length"] == 21
        assert v["truncated"] is True
        assert render_value(v) == '"verifyPassword_e…"'

    def test_instance_record(self):
        v = parse_result_value("{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$1002df0e0b000000)}")
        assert v == {"type": "object", "ptr": "0xb0edf0210"}

    def test_list_with_pointer(self):
        v = parse_result_value("[FALSE,{want=ocid,from=NULL-impl,form=ID  ,seld=optr(8/$1002df0e0b000000)}]")
        assert v == [False, {"type": "object", "ptr": "0xb0edf0210"}]
        assert render_value(v, lambda p: "error1") == "{false, error1}"

    def test_out_parameter_reference(self):
        c = call(INSTANCE_VERIFY_PASSWORD)
        assert c["args"][1] == {"type": "reference"}

    def test_optr_is_little_endian(self):
        assert optr_to_ptr("8/$e02bbf0e0b000000") == "0xb0ebf2be0"

    def test_decode_unknown_typed_value_is_raw(self):
        assert decode_value({"__type__": "asid", "__raw__": "16/$01"}) == {"type": "raw", "value": "asid(16/$01)"}


class TestEnrich:
    def test_bridge_clone_gets_objc_not_clone(self):
        r = enrich_unified_log({"eventMessage": CLASS_OD_SESSION, "processImagePath": "/x/Script Editor"})
        assert "clone" not in r["appleEvent"]
        objc = r["appleEvent"]["objc"]
        assert objc["applescript"] == "ODSession's defaultSession()"
        assert objc["raw"].startswith("{ascr,psbr")
        assert objc["receiver_kind"] == "class"

    def test_failed_lookup_event_is_a_bridge_call(self):
        r = enrich_unified_log({"eventMessage": FAILED_LOOKUP, "processImagePath": "/x/Script Editor"})
        assert "event" not in r["appleEvent"]
        objc = r["appleEvent"]["objc"]
        assert objc["lookup_failed"] is True
        assert objc["applescript"] == "odSession's defaultSession()"

    def test_quoted_clone_unchanged(self):
        r = enrich_unified_log({"eventMessage": 'cloneForCompatability(src="ls -la /tmp" dst=0x1'})
        assert r["appleEvent"] == {"clone": "ls -la /tmp"}

    def test_other_clone_sources_take_the_clone_path(self):
        message = "cloneForCompatability(src=[utxt(10/$610064006d0069006e00)] dst=0x1"
        r = enrich_unified_log({"eventMessage": message})
        assert r["appleEvent"] == {"clone": extract_clone_src(message)}


class TestAstObjectValues:
    """Regular Apple events can carry AppleScriptObjC values too."""

    def test_no_not_implemented_warnings(self, caplog):
        from aemonitor.ast import get_expression

        for value, source in [
            ({"__type__": "optr", "__raw__": "8/$e02bbf0e0b000000"}, "«object 0xb0ebf2be0»"),
            (
                {"form": "ID", "want": "ocid", "seld": {"__type__": "optr", "__raw__": "8/$e02bbf0e0b000000"}, "from": "NULL-impl"},
                "«object 0xb0ebf2be0»",
            ),
            ("msng", "missing value"),
            ("obj", "(reference)"),
        ]:
            assert get_expression(value).to_source() == source
        assert "NOT IMPLEMENTED" not in caplog.text
