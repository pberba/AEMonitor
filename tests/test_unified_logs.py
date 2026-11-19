import json
import pytest

from aemonitor.unified_logs import (
    decode_utxt_raw,
    extract_apple_events,
    extract_clone_src,
    enrich_unified_log,
    is_private_only,
)


class TestExtractCloneSrc:
    """Tests for extract_clone_src from unified_logs."""

    def test_quoted_string_src(self):
        """cloneForCompatability with quoted src extracts the string."""
        msg = "cloneForCompatability(src=\"test -d '/Applications/Ledger Live.app'\" dst=0x16ef41dbc"
        assert extract_clone_src(msg) == "test -d '/Applications/Ledger Live.app'"

    def test_utxt_src(self):
        """cloneForCompatability with utxt src decodes UTF-16LE."""
        msg = "cloneForCompatability(src=utxt(84/$540068006500200063006f006d006d0061006e00640020006500780069007400...) dst=0x16ef41cc4"
        result = extract_clone_src(msg)
        assert result == "The command exit"

    def test_not_clone_returns_none(self):
        """Non-clone messages return None."""
        assert extract_clone_src("sendToSelf(), event={syso,exec...}") is None
        assert extract_clone_src("") is None

    def test_utxt_string_list_src(self):
        """A list of utxt strings is decoded and joined (the bare `[` used to drop it)."""
        msg = (
            "cloneForCompatability(src=[utxt(44/$68007400740070003a002f002f006c006f0063"
            "0061006c0068006f0073007400), utxt(22/$2f0074006d0070002f00610065007400650073"
            "007400)] dst=0x0"
        )
        assert extract_clone_src(msg) == "http://localhost /tmp/aetest"

    def test_compiled_javascript_scpt_placeholder(self):
        """scpt carrying the JsOsaDAS magic becomes a typed placeholder (body is truncated)."""
        msg = (
            "cloneForCompatability(src=scpt(6864/$4a734f7361444153312e3030312e30306270"
            "6c6973743030d101025673637269...) dst=0x16b9be954"
        )
        result = extract_clone_src(msg)
        assert result is not None
        assert "compiled JavaScript script" in result
        assert "scpt" in result and "6864 bytes" in result

    def test_compiled_applescript_direct_object_placeholder(self):
        """A ---- direct object carrying FasdUAS magic is labelled compiled AppleScript."""
        msg = (
            "cloneForCompatability(src=----(45915/$4661736455415320312e3130312e31300e00"
            "0000040fffff...) dst=0x0"
        )
        result = extract_clone_src(msg)
        assert result is not None and "compiled AppleScript script" in result

    def test_record_src_decompiles_to_applescript(self):
        """A structured record src is routed through the decompiler instead of dropped."""
        msg = (
            "cloneForCompatability(src={aevt,odoc target='psn '[Finder] "
            "{----=[utxt(10/$480065006c006c006f00)]} returnID=1} dst=0x0"
        )
        result = extract_clone_src(msg)
        assert result is not None
        assert 'tell application "Finder"' in result and '"Hello"' in result

    def test_opaque_descriptors_still_dropped(self):
        """Pointers and bare type codes carry no command content and stay dropped."""
        assert extract_clone_src("cloneForCompatability(src=optr(8/$2063670a0b000000) dst=0x0") is None
        assert extract_clone_src("cloneForCompatability(src=msng dst=0x0") is None


class TestIsPrivateOnly:
    """A record is 'private-only' when all its content comes from %{private} fields."""

    def test_clone_format_string_is_private_only(self):
        # Clones are always src=%{private}s: redacted to nothing on stock macOS.
        assert is_private_only("%{public}scloneForCompatability(src=%{private}s dst=%p")

    def test_public_apple_event_is_not_private_only(self):
        # event=%s / reply=%s are public, so Apple Events survive on stock macOS.
        assert not is_private_only("%{public}sfinishAndSendReply: %d event=%s reply=%s")

    def test_partially_private_is_not_private_only(self):
        # Has public content alongside the private field -> still partly visible.
        assert not is_private_only("Resource lookup at %{private}@\n\tRequest: %{public}@")

    def test_empty_format_string(self):
        assert not is_private_only("")

    def test_enrich_sets_private_only_flag(self):
        clone = enrich_unified_log(
            {
                "eventMessage": "cloneForCompatability(src=utxt(22/$2f0074006d007000) dst=0x0",
                "formatString": "%{public}scloneForCompatability(src=%{private}s dst=%p",
                "processImagePath": "/usr/bin/osascript",
            }
        )
        assert clone["private_only"] is True

    def test_decode_utxt_raw_full_hex(self):
        """decode_utxt_raw decodes full UTF-16LE hex."""
        inner = "84/$540068006500200063006f006d006d0061006e00640020006500780069007400"
        assert decode_utxt_raw(inner) == "The command exit"

    def test_decode_utxt_raw_truncated(self):
        """decode_utxt_raw handles truncated hex with ..."""
        inner = (
            "84/$540068006500200063006f006d006d0061006e00640020006500780069007400..."
        )
        assert decode_utxt_raw(inner) == "The command exit"


class TestExtractAppleEvents:
    """Tests for extract_apple_events from unified_logs."""

    def test_empty_message(self):
        """Empty message returns empty dict (no keys)."""
        assert extract_apple_events("") == {}

    def test_send_to_self_with_event_and_reply(self):
        """sendToSelf() log: event (braced) and reply (0xNULL-impl)."""
        msg = """sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082} reply=0xNULL-impl sendMode=1043 timeout=7200"""
        result = extract_apple_events(msg)
        assert (
            result["event"]
            == "{syso,exec target='psn '[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082}"
        )
        assert "reply" not in result

    def test_reply_of_send_to_self(self):
        """AE2000 Reply of SendToSelf: reply only (braced)."""
        msg = """AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {errn=1,errs=utxt(84/$540068006500200063006f006d006d0061006e00640020006500780069007400...)} returnID=-1668}"""
        result = extract_apple_events(msg)
        assert "event" not in result
        assert (
            result["reply"]
            == "{aevt,ansr target='psn '[osascript] {errn=1,errs=utxt(84/$540068006500200063006f006d006d0061006e00640020006500780069007400...)} returnID=-1668}"
        )

    def test_finish_and_send_reply(self):
        """finishAndSendReply: event (braced) and reply (NULL-impl)."""
        msg = """finishAndSendReply: 0 event={aevt,rapp target=Dock {frnt=FALSE,disp=1} attr:{optk=[keyw(4/$746e7266)]} returnID=17066} reply=NULL-impl"""
        result = extract_apple_events(msg)
        assert (
            result["event"]
            == "{aevt,rapp target=Dock {frnt=FALSE,disp=1} attr:{optk=[keyw(4/$746e7266)]} returnID=17066}"
        )
        assert result["reply"] == "NULL-impl"

    def test_send_to_modern_process(self):
        """OSStatus sendToModernProcess: event only (deeply nested braced)."""
        msg = """OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:58491/0xe47b send:2 limit:0) msgID=0 timeout 7200 event={core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(28/$4c0075004c0075005f0034002e0032002e0030002e0064006d006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$610064006d0069006e00),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498}"""
        result = extract_apple_events(msg)
        assert (
            result["event"]
            == "{core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(28/$4c0075004c0075005f0034002e0032002e0030002e0064006d006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$610064006d0069006e00),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498}"
        )
        assert "reply" not in result


# Real unified log messages from Apple Event monitoring
MESSAGES = [
    # ears/lfdr - list folder
    "sendToSelf(), event={ears,lfdr target='psn '[osascript] {lfiv=fals(0/$),----=utxt(154/$2f00550073006500720073002f00610064006d0069006e002f004c0069006200...)} attr:{subj=NULL-impl,csig=65536} returnID=-31737} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "sendToSelf(), event={ears,lfdr target='psn '[osascript] {lfiv=fals(0/$),----=utxt(96/$2f00550073006500720073002f00610064006d0069006e002f004c0069006200...)} attr:{subj=NULL-impl,csig=65536} returnID=-2680} reply=0xNULL-impl sendMode=1043 timeout=7200",
    # syso/exec - do shell script
    "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(112/$6300700020007e002f004c006900620072006100720079002f004b0065007900...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=9906} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {----=\"\"} returnID=9906}",
    "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(80/$6300700020002d00720020007e002f002e00730073006800200027002f007400...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=14673} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {----=\"\"} returnID=14673}",
    "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(80/$6300700020002d00720020007e002f002e00610077007300200027002f007400...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=3398} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {errn=1,errs=\"cp: /Users/admin/.aws: No such file or directory\"} returnID=3398}",
    "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(80/$6d006b0064006900720020002d007000200027002f0074006d0070002f007300...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=16129} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {----=\"\"} returnID=16129}",
    # ears/ffdr - path to
    "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:58491/0xe47b send:2 limit:0) msgID=0 timeout 7200 event={ears,ffdr target='psn '[Finder] {from=fldu,rtyp=ctxt,----=dlib} attr:{subj=NULL-impl,csig=65536} returnID=16929}",
    "finishAndSendReply: 0 event={ears,ffdr target=osascript {from=fldu,rtyp=ctxt,----=dlib} attr:{subj=NULL-impl,csig=65536} returnID=16929} reply={aevt,ansr target=osascript {----=utxt(66/$4d006100630069006e0074006f00730068002000480044003a00550073006500...)} returnID=16929}",
    "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:118539/0x1cf0b send:2 limit:0) msgID=1 timeout 7200 event={aevt,ansr target=osascript {----=utxt(66/$4d006100630069006e0074006f00730068002000480044003a00550073006500...)} returnID=16929}",
    # core/getd - name extension
    "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:58491/0xe47b send:2 limit:0) msgID=0 timeout 7200 event={core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(28/$4c0075004c0075005f0034002e0032002e0030002e0064006d006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$610064006d0069006e00),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498}",
    "finishAndSendReply: 0 event={core,getd target=osascript {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(28/$4c0075004c0075005f0034002e0032002e0030002e0064006d006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$610064006d0069006e00),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498} reply={aevt,ansr target=osascript {----=utxt(6/$64006d006700)} returnID=24498}",
    "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:130083/0x1fc23 send:2 limit:0) msgID=1 timeout 7200 event={aevt,ansr target=osascript {----=utxt(6/$64006d006700)} returnID=24498}",
    # syso/exec rm -rf
    "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(34/$72006d0020002d007200660020002f0074006d0070002f00730079006e006300...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=28046} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {----=\"\"} returnID=28046}",
    "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(82/$740065007300740020002d006400200027002f004100700070006c0069006300...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-1668} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {errn=1,errs=utxt(84/$540068006500200063006f006d006d0061006e00640020006500780069007400...)} returnID=-1668}",
]


class TestEnrichUnifiedLogWithRealMessages:
    """Tests for enrich_unified_log using real Apple Event monitoring messages."""

    def test_enrich_processes_all_messages(self):
        """Each message with event= or reply= runs through enrich_unified_log without crashing."""
        total_enriched = 0
        for msg in MESSAGES:
            entry = {"eventMessage": msg, "processImagePath": "/usr/bin/osascript"}
            enriched = enrich_unified_log(entry.copy())
            if enriched is not None and "appleEvent" in enriched:
                ae = enriched["appleEvent"]
                for key in ("event", "reply"):
                    if key in ae and ae[key].get("applescript"):
                        total_enriched += 1
                        assert isinstance(ae[key]["applescript"], str)
                        assert len(ae[key]["applescript"]) > 0
        assert (
            total_enriched >= 1
        ), "Expected at least one successfully enriched event/reply"

    def test_enrich_ears_ffdr_finder(self):
        """ears/ffdr Finder path to user domain produces valid applescript."""
        msg = "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:58491/0xe47b send:2 limit:0) msgID=0 timeout 7200 event={ears,ffdr target='psn '[Finder] {from=fldu,rtyp=ctxt,----=dlib} attr:{subj=NULL-impl,csig=65536} returnID=16929}"
        entry = {"eventMessage": msg}
        enriched = enrich_unified_log(entry)
        assert enriched is not None
        assert "event" in enriched["appleEvent"]
        applescript = enriched["appleEvent"]["event"]["applescript"]
        assert "Finder" in applescript
        assert "path to" in applescript or "folder" in applescript

    def test_enrich_core_getd_finder(self):
        """core/getd Finder name extension produces valid applescript."""
        msg = "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:58491/0xe47b send:2 limit:0) msgID=0 timeout 7200 event={core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(28/$4c0075004c0075005f0034002e0032002e0030002e0064006d006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$610064006d0069006e00),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498}"
        entry = {"eventMessage": msg}
        enriched = enrich_unified_log(entry)
        assert enriched is not None
        assert "event" in enriched["appleEvent"]
        applescript = enriched["appleEvent"]["event"]["applescript"]
        assert "Finder" in applescript
        assert "LuLu_4.2.0.dmg" in applescript or "name extension" in applescript

    def test_enrich_syso_exec_rm(self):
        """syso/exec rm -rf produces valid applescript."""
        msg = "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(34/$72006d0020002d007200660020002f0074006d0070002f00730079006e006300...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=28046} reply=0xNULL-impl sendMode=1043 timeout=7200"
        entry = {"eventMessage": msg, "processImagePath": "/usr/bin/osascript"}
        enriched = enrich_unified_log(entry)
        assert enriched is not None
        assert "event" in enriched["appleEvent"]
        applescript = enriched["appleEvent"]["event"]["applescript"]
        assert "do shell script" in applescript
        assert "rm -rf" in applescript or "/tmp/sync" in applescript


# Sample unified log events from Apple Events subsystem (JSON format)
SAMPLE_UNIFIED_LOG_EVENTS = [
    '{"eventMessage":"sendToSelf(), event={syso,exec target=\'psn \'[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082} reply=0xNULL-impl sendMode=1043 timeout=7200"}',
    '{"eventMessage":"sendToSelf(), event={fndr,gstl target=\'psn \'[osascript] {----=utxt(8/$5500530045005200)} attr:{subj=NULL-impl,csig=65536} returnID=20941} reply=0xNULL-impl sendMode=1043 timeout=7200"}',
    '{"eventMessage":"sendToSelf(), event={syso,exec target=\'psn \'[osascript] {----=utxt(72/$6500630068006f002000240028002800520041004e0044004f004d0020002500...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=27111} reply=0xNULL-impl sendMode=1043 timeout=7200"}',
    '{"eventMessage":"sendToSelf(), event={syso,exec target=\'psn \'[osascript] {----=utxt(52/$6400730063006c0020002e00200061007500740068006f006e006c0079002000...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-10193} reply=0xNULL-impl sendMode=1043 timeout=7200"}',
    # syso,dlog - display dialog
    (
        '{"eventMessage":"sendToSelf(), event={syso,dlog target=\'psn \'[osascript] {dtxt=utxt(0/$),disp=\\"'
        "file:///System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/LockedIcon.icns"
        '\\",btns=[utxt(16/$43006f006e00740069006e0075006500)],dflt=utxt(16/$43006f006e00740069006e0075006500),'
        "givu=150,appr=utxt(36/$530079007300740065006d00200050007200650066006500720065006e006300...),"
        "htxt=true(0/$),----=utxt(128/$5200650071007500690072006500640020004100700070006c00690063006100...)} "
        "attr:{subj=NULL-impl,csig=65536,shas=[(sandboxAnnotation, len=257 extensionHash=32/$cef0da32b902cb2db025bf6f5ba848dcee9d8e724783e435366d01c5d69238ea)]} "
        'returnID=17013} reply=0xNULL-impl sendMode=1043 timeout=7200"}'
    ),
]


class TestEnrichUnifiedLogWithSampleEvents:
    """Tests for enrich_unified_log using real unified log sample events."""

    @pytest.mark.parametrize("event_json", SAMPLE_UNIFIED_LOG_EVENTS)
    def test_enrich_parses_and_decompiles(self, event_json):
        """Each sample event parses and produces decompiled AppleScript."""
        log_entry = json.loads(event_json)
        enriched_log = enrich_unified_log(log_entry)
        assert "appleEvent" in enriched_log
        assert "event" in enriched_log["appleEvent"]
        decompiled = enriched_log["appleEvent"]["event"]["applescript"]
        assert isinstance(decompiled, str)
        assert len(decompiled) > 0
        assert "osascript" in decompiled

    def test_syso_exec_killall_decompiles_to_do_shell_script(self):
        """syso/exec killall Terminal -> do shell script."""
        log = json.loads(SAMPLE_UNIFIED_LOG_EVENTS[0])
        enriched_log = enrich_unified_log(log)
        decompiled = enriched_log["appleEvent"]["event"]["applescript"]
        assert "do shell script" in decompiled
        assert "killall" in decompiled or "Terminal" in decompiled
        assert -27082 == enriched_log["appleEvent"]["event"]["return_id"]

    def test_fndr_gstl_decompiles(self):
        """fndr/gstl (Finder get something) decompiles."""
        log = json.loads(SAMPLE_UNIFIED_LOG_EVENTS[1])
        enriched_log = enrich_unified_log(log)
        decompiled = enriched_log["appleEvent"]["event"]["applescript"]
        assert "osascript" in decompiled

    def test_syso_exec_echo_decompiles(self):
        """syso/exec echo $((RANDOM... decompiles to do shell script."""
        log = json.loads(SAMPLE_UNIFIED_LOG_EVENTS[2])
        enriched_log = enrich_unified_log(log)
        decompiled = enriched_log["appleEvent"]["event"]["applescript"]
        assert "do shell script" in decompiled

    def test_syso_exec_dscl_decompiles(self):
        """syso/exec dscl . authonly decompiles to do shell script."""
        log = json.loads(SAMPLE_UNIFIED_LOG_EVENTS[3])
        enriched_log = enrich_unified_log(log)
        decompiled = enriched_log["appleEvent"]["event"]["applescript"]
        assert "do shell script" in decompiled

    def test_syso_dlog_display_dialog_decompiles(self):
        """syso/dlog (display dialog) decompiles."""
        log = json.loads(SAMPLE_UNIFIED_LOG_EVENTS[4])
        enriched_log = enrich_unified_log(log)
        decompiled = enriched_log["appleEvent"]["event"]["applescript"]
        assert "osascript" in decompiled
        assert "display dialog" in decompiled
        assert "hidden answer" in decompiled
        assert "giving up after 150 with title" in decompiled
        assert "System Preferenc..." in decompiled
