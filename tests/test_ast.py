import pytest

from aemonitor.aedebug import parse_apple_event_debug
from aemonitor.ast import derive_ast


def _parse_and_derive(s: str) -> str:
    """Parse Apple Event string and derive AST source."""
    event = parse_apple_event_debug(s)
    return derive_ast(event)


class TestDeriveAst:
    """Tests for derive_ast using real Apple Event inputs."""

    def test_aevt_ansr_osascript_utxt(self):
        """aevt/ansr: osascript target with utxt direct object (Macintosh HD path)."""
        s = "{aevt,ansr target=osascript {----=utxt(66/$4d006100630069006e0074006f00730068002000480044003a00550073006500...)} returnID=16929}"
        result = _parse_and_derive(s)
        assert "aevtansr" in result
        assert "Macintosh HD:Use" in result

    def test_ears_ffdr_finder_dlib(self):
        """ears/ffdr: Finder target with from/rtyp/---- (path to user domain)."""
        s = "{ears,ffdr target='psn '[Finder] {from=fldu,rtyp=ctxt,----=dlib} attr:{subj=NULL-impl,csig=65536} returnID=16929}"
        result = _parse_and_derive(s)
        assert "Finder" in result
        assert "path to" in result
        assert "folder" in result
        assert "user domain" in result

    def test_aevt_ansr_osascript_errn(self):
        """aevt/ansr: osascript target with errn error code."""
        s = "{aevt,ansr target=osascript {errn=-1708} returnID=-7695}"
        result = _parse_and_derive(s)
        assert "aevtansr" in result
        assert "-1708" in result

    def test_syso_exec_osascript_utxt(self):
        """syso/exec: osascript target with utxt command (do shell script)."""
        s = "{syso,exec target='psn '[osascript] {----=utxt(34/$72006d0020002d007200660020002f0074006d0070002f00730079006e006300...)}"
        result = _parse_and_derive(s)
        assert "osascript" in result
        assert "do shell script" in result
        assert "rm -rf /tmp/sync" in result

    def test_core_getd_finder_abso(self):
        """core/getd: Finder target with abso (reversed ASCII, e.g. abso(4/$206c6c61) -> "all ")."""
        s = "{core,getd target='psn '[Finder] {----={form=indx,want=file,seld=abso(4/$206c6c61),from={form=prop,want=prop,seld=desk,from=NULL-impl}}} attr:{csig=65536} returnID=-25481}"
        result = _parse_and_derive(s)
        assert "Finder" in result
        assert "file" in result
        assert "all" in result
        assert "desktop" in result

    def test_utxt_truncated_hex_does_not_crash(self):
        """utxt with truncated hex (odd bytes, e.g. utxt(6/$74006d0000)) decodes with replacement char instead of crashing."""
        s = "{aevt,ansr target=osascript {----={want=docf,from={want=cfol,from={want=cfol,from={want=cfol,from={want=cobj,from={want=prop,from=NULL-impl,form=prop,seld=sdsk},form=name,seld=utxt(14/$7000720069007600610074006500)},form=name,seld=utxt(6/$74006d0000)},form=name,seld=utxt(22/$730079006e0063003100300031003600360036003400)},form=name,seld=utxt(10/$4e006f00740065007300)},form=name,seld=utxt(40/$4e006f0074006500530074006f00720065002e00730071006c00690074006500...)},errn=0} returnID=-3183}"
        result = _parse_and_derive(s)
        assert "aevtansr" in result
        assert "NoteStore.sqlite" in result
        assert (
            "tm" in result
        )  # Truncated utxt(6/$74006d0000) decodes to "tm" + replacement char

    def test_aevt_ansr_osascript_nested_docf_path(self):
        """aevt/ansr: osascript target with nested ---- (docf/cfol path: NoteStore.sqlite of Notes of sync... of tmp of private)."""
        s = "{aevt,ansr target=Finder {----={want=docf,from={want=cfol,from={want=cfol,from={want=cfol,from={want=cobj,from={want=prop,from=NULL-impl,form=prop,seld=sdsk},form=name,seld=utxt(14/$7000720069007600610074006500)},form=name,seld=utxt(6/$74006d007000)},form=name,seld=utxt(22/$730079006e0063003100300031003600360036003400)},form=name,seld=utxt(10/$4e006f00740065007300)},form=name,seld=utxt(40/$4e006f0074006500530074006f00720065002e00730071006c00690074006500...)},errn=0} returnID=-3183}"
        result = _parse_and_derive(s)
        assert "NoteStore.sqlite" in result
        assert "Notes" in result
        assert "sync1016664" in result
        assert "tmp" in result
        assert "private" in result

    def test_core_getd_finder_nested_objdesc(self):
        """core/getd: deeply nested object spec targeting Finder (name extension of document)."""
        s = "{core,getd target='psn '[Finder] {----={form=prop,want=prop,seld=nmxt,from={form=name,want=docf,seld=utxt(20/$730061006d0070006c0065002e0070006e006700),from={form=name,want=cfol,seld=utxt(18/$44006f0077006e006c006f00610064007300),from={form=name,want=cfol,seld=utxt(10/$7500730065007200),from={form=name,want=cfol,seld=utxt(10/$55007300650072007300),from={form=prop,want=prop,seld=sdsk,from=NULL-impl}}}}}}} attr:{csig=65536} returnID=24498}"
        result = _parse_and_derive(s)

        assert "Finder" in result
        assert "coregetd" in result
        assert "sample.png" in result and "name extension" in result
        assert "startup disk" in result and "Downloads" in result

    def test_syso_dlog_display_dialog(self):
        """syso/dlog: display dialog with LockedIcon, Continue button, System Preferences, Required Application."""
        s = "{syso,dlog target='psn '[osascript] {dtxt=utxt(0/$),disp=\"file:///System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/LockedIcon.icns\",btns=[utxt(16/$43006f006e00740069006e0075006500)],dflt=utxt(16/$43006f006e00740069006e0075006500),givu=150,appr=utxt(36/$530079007300740065006d00200050007200650066006500720065006e006300...),htxt=true(0/$),----=utxt(128/$5200650071007500690072006500640020004100700070006c00690063006100...)} attr:{subj=NULL-impl,csig=65536,shas=[(sandboxAnnotation, len=257 extensionHash=32/$cef0da32b902cb2db025bf6f5ba848dcee9d8e724783e435366d01c5d69238ea)]} returnID=17013}"
        result = _parse_and_derive(s)

        assert "osascript" in result
        assert "syso" in result or "dlog" in result or "display dialog" in result
        assert "Continue" in result
        assert '{"Continue"}' in result
        assert "System" in result or "Preferenc" in result
        assert "Required" in result or "Applic" in result

    def test_core_setd_terminal_set_visible_false(self):
        """core/setd: Terminal target setting visible of front window to false."""
        s = "{core,setd target='psn '[Terminal] {data=fals(0/$),----={form=prop,want=prop,seld=pvis,from={form=indx,want=cwin,seld=1,from=NULL-impl}}} attr:{csig=65536} returnID=-15080}"
        result = _parse_and_derive(s)
        assert "Terminal" in result
        assert "visible" in result
        assert "windows 1" in result
        assert "false" in result

    def test_core_dosc_terminal_do_script(self):
        """core/dosc: Terminal target running do script with touch command."""
        s = "{core,dosc target='psn '[Terminal] {----=utxt(38/$74006f0075006300680020002f0074006d0070002f0074006500730074002e00...)} attr:{subj=NULL-impl,csig=65536} returnID=11442}"
        result = _parse_and_derive(s)
        assert "Terminal" in result
        assert "do script" in result
        assert "touch /tmp/test." in result

    def test_aevt_oapp_port_target_no_tell_application_none(self):
        """aevt/oapp: port target uses UNKNOWN, must not produce 'tell application \"NONE\"'."""
        s = "{aevt,oapp target=port(4/$6b610000) {prdt={disp=1},aapd=TRUE} attr:{optk=[keyw(4/$74647270)],tokn=[sess=100003 pid=368 uid:501,501,501 g:20,20 pV:880]} returnID=-6515}"
        result = _parse_and_derive(s)
        assert 'tell application "None"' not in result
        assert 'tell application "NONE"' not in result
