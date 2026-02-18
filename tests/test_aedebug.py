import pytest

from aemonitor.aedebug import parse_apple_event_debug


class TestParseAppleEventDebug:
    """Tests for parse_apple_event_debug using real Apple Event inputs."""

    def test_aevt_ansr_osascript_utxt(self):
        """aevt/ansr: osascript target with utxt direct object."""
        s = "{aevt,ansr target=osascript {----=utxt(66/$4d006100630069006e0074006f00730068002000480044003a00550073006500...)} returnID=16929}"
        result = parse_apple_event_debug(s)
        assert result["event_class"] == "aevt"
        assert result["event_id"] == "ansr"
        assert result["return_id"] == 16929
        assert result["target"] == "osascript"
        assert result["params"]["----"]["__type__"] == "utxt"
        assert (
            "66/$4d006100630069006e0074006f00730068002000480044003a00550073006500..."
            in result["params"]["----"]["__raw__"]
        )

    def test_ears_ffdr_finder_dlib(self):
        """ears/ffdr: 'psn '[Finder] target with from/rtyp/---- and attr."""
        s = "{ears,ffdr target='psn '[Finder] {from=fldu,rtyp=ctxt,----=dlib} attr:{subj=NULL-impl,csig=65536} returnID=16929}"
        result = parse_apple_event_debug(s)
        assert result["event_class"] == "ears"
        assert result["event_id"] == "ffdr"
        assert result["return_id"] == 16929
        assert result["target"] == "Finder"
        assert result["params"]["from"] == "fldu"
        assert result["params"]["rtyp"] == "ctxt"
        assert result["params"]["----"] == "dlib"
        assert result["attr"] == {"subj": "NULL-impl", "csig": 65536}

    def test_aevt_ansr_osascript_errn(self):
        """aevt/ansr: osascript target with errn error code."""
        s = "{aevt,ansr target=osascript {errn=-1708} returnID=-7695}"
        result = parse_apple_event_debug(s)
        assert result["event_class"] == "aevt"
        assert result["event_id"] == "ansr"
        assert result["return_id"] == -7695
        assert result["target"] == "osascript"
        assert result["params"]["errn"] == -1708

    def test_syso_exec_osascript_utxt(self):
        """syso/exec: 'psn '[osascript] target with utxt command."""
        s = "{syso,exec target='psn '[osascript] {----=utxt(34/$72006d0020002d007200660020002f0074006d0070002f00730079006e006300...)}"
        result = parse_apple_event_debug(s)
        assert result["event_class"] == "syso"
        assert result["event_id"] == "exec"
        assert result["target"] == "osascript"
        assert result["params"]["----"]["__type__"] == "utxt"
        assert (
            "34/$72006d0020002d007200660020002f0074006d0070002f00730079006e006300..."
            in result["params"]["----"]["__raw__"]
        )

    def test_core_getd_finder_nested_objdesc(self):
        """core/getd: deeply nested object spec (form/want/seld/from) targeting Finder."""
        s = "{core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(20/$730061006d0070006c0065002e0070006e006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$7500730065007200),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498}"
        result = parse_apple_event_debug(s)
        assert result["event_class"] == "core"
        assert result["event_id"] == "getd"
        assert result["return_id"] == 24498
        assert result["target"] == "Finder"
        assert result["attr"] == {"csig": 65536}

        params = result["params"]["----"]
        assert params["form"] == "prop"
        assert params["want"] == "prop"
        assert params["seld"] == "nmxt"
        assert "form" in params["from"]
        assert params["from"]["form"] == "name"
        assert params["from"]["want"] == "docf"
        assert params["from"]["seld"]["__type__"] == "utxt"
        assert (
            "20/$730061006d0070006c0065002e0070006e006700"
            in params["from"]["seld"]["__raw__"]
        )
