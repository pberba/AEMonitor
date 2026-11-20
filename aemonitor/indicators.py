"""
Suspicious-behaviour indicators built on AppleScriptObjC bridge calls.

Each indicator is a lead, not a verdict: NSAlert and NSURLSession have plenty of
legitimate uses in admin scripts. Scoring and combining them is future work; this
layer only names what it saw, with the returnIDs of the supporting calls.

Names, selectors and strings in the log are cut to 16 characters, so everything here
matches on prefixes, case-sensitively.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from aemonitor.objc import UTXT_LOGGED_CHARS
from aemonitor.objc_correlate import process_key

# Bounds so a long live session doesn't grow without limit
MAX_PROCS = 256  # processes tracked at once; the least recently active is forgotten
MAX_CALLS = 4096  # calls (and tainted pointers) remembered per process
MAX_RIDS = 32  # supporting returnIDs kept per list


def _append_capped(items: List[Any], item: Any, limit: int = MAX_RIDS) -> None:
    items.append(item)
    if len(items) > limit:
        del items[0]


def _set_capped(mapping: Dict[Any, Any], key: Any, value: Any, limit: int = MAX_CALLS) -> None:
    mapping[key] = value
    if len(mapping) > limit:
        del mapping[next(iter(mapping))]  # oldest (dicts keep insertion order)


@dataclass(frozen=True)
class IndicatorSpec:
    name: str
    description: str
    # (label, string) prefixes this indicator matches on; used for the raw hex needles
    needles: Tuple[str, ...] = ()


SPECS: Dict[str, IndicatorSpec] = {
    s.name: s
    for s in [
        IndicatorSpec("objc.ui.alert", "NSAlert shown with runModal", ("NSAlert", "runModal")),
        IndicatorSpec(
            "objc.cred.secure_field", "Secure (password) text field created", ("NSSecureTextFiel",)
        ),
        IndicatorSpec(
            "objc.cred.prompt_with_input",
            "Alert with a text field accessory shown, then its value read",
            ("setAccessoryView", "stringValue"),
        ),
        IndicatorSpec(
            "objc.cred.window_raised",
            "Window raised above normal windows",
            ("NSStatusWindowLe", "NSScreenSaverWin", "NSPopUpMenuWindo", "NSModalPanelWind"),
        ),
        IndicatorSpec(
            "objc.cred.od_verify",
            "Password checked through OpenDirectory",
            ("ODSession", "ODNode", "verifyPassword_e"),
        ),
        IndicatorSpec(
            "objc.cred.verify_result", "Result of an OpenDirectory password check", ("verifyPassword_e",)
        ),
        IndicatorSpec(
            "objc.cred.reprompt_loop",
            "Password prompt shown again after a failed check",
        ),
        IndicatorSpec(
            "objc.cred.cleartext_leak",
            "Text read from an input field is visible in the log",
            ("stringValue",),
        ),
        IndicatorSpec(
            "objc.cred.saved_to_disk",
            "Text read from an input field written to a file",
            ("writeToFile_atom",),
        ),
        IndicatorSpec(
            "objc.lure.app_icon",
            "Alert given a custom icon loaded from a bundle or file",
            ("pathForResource_", "initByReferencin", "setIcon_"),
        ),
        IndicatorSpec("objc.net.url", "URL created", ("URLWithString_",)),
        IndicatorSpec(
            "objc.net.session",
            "HTTP request through NSURLSession or NSData",
            (
                "NSURLSession",
                "NSURLSessionConf",
                "NSMutableURLRequ",
                "dataTaskWithRequ",
                "dataTaskWithURL_",
                "dataWithContents",
            ),
        ),
        IndicatorSpec("objc.net.post", "HTTP POST or request body set", ("setHTTPMethod_", "setHTTPBody_")),
        IndicatorSpec(
            "objc.file.stage",
            "Files or directories created or written",
            ("createDirectoryA", "createFileAtPath", "writeToFile_atom", "setAttributes_of"),
        ),
        IndicatorSpec(
            "objc.exec.task",
            "Process or application launched",
            ("NSTask", "launchedTaskWith", "launchAndReturnE", "launchApplicati"),
        ),
        IndicatorSpec(
            "objc.recon.region",
            "Locale, time zone and keyboard layouts read (region check)",
            ("currentLocale", "systemTimeZone", "com.apple.HITool", "AppleEnabledInpu"),
        ),
        IndicatorSpec(
            "objc.ui.headless_to_gui",
            "Activation policy changed and app brought to the front",
            ("setActivationPol", "activateIgnoring"),
        ),
        IndicatorSpec(
            "objc.bridge.failed_lookup",
            "Bridge call to a class that does not exist",
        ),
    ]
}

_RAISED_LEVELS = SPECS["objc.cred.window_raised"].needles
_FILE_STAGE = SPECS["objc.file.stage"].needles
_NET_CLASSES = ("NSURLSession", "NSURLSessionConf", "NSMutableURLRequ")
_NET_SELECTORS = ("dataTaskWithRequ", "dataTaskWithURL_", "dataWithContents")
_TEXT_FIELDS = ("NSTextField", "NSSecureTextFiel")


def hex_needle(s: str) -> str:
    """The UTF-16LE hex a string appears as in a raw eventMessage (first 16 chars)."""
    return s[:UTXT_LOGGED_CHARS].encode("utf-16le").hex()


def hex_needles() -> List[Tuple[str, str, str]]:
    """(indicator, string, hex) for every prefix the indicators match on."""
    out = []
    for spec in SPECS.values():
        for s in spec.needles:
            out.append((spec.name, s, hex_needle(s)))
    return out


@dataclass
class Finding:
    name: str
    process_id: Any
    process: str
    return_ids: List[Any]
    detail: str = ""

    @property
    def description(self) -> str:
        return SPECS[self.name].description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.name,
            "description": self.description,
            "processID": self.process_id,
            "process": self.process,
            "return_ids": self.return_ids,
            "detail": self.detail,
        }


def _text(v: Any) -> Optional[str]:
    if isinstance(v, dict) and v.get("type") == "text":
        return v.get("value")
    return None


def _const(v: Any) -> Optional[str]:
    if isinstance(v, dict) and v.get("type") == "constant":
        return v.get("name")
    return None


def _ptr(v: Any) -> Optional[str]:
    if isinstance(v, dict) and v.get("type") == "object":
        return v.get("ptr")
    return None


def _first_bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, list) and v and isinstance(v[0], bool):
        return v[0]
    return None


@dataclass
class _ProcState:
    process: str = ""
    fired: Dict[str, Finding] = field(default_factory=dict)
    calls: Dict[Any, Dict[str, Any]] = field(default_factory=dict)  # return_id -> call
    # alert / prompt
    alert_rids: List[Any] = field(default_factory=list)
    text_field_rids: List[Any] = field(default_factory=list)
    accessory_rid: Any = None
    prompt_modal_rid: Any = None
    prompts: int = 0
    prompt_rids: List[Any] = field(default_factory=list)
    failed_check_since_prompt: bool = False
    failed_check_rids: List[Any] = field(default_factory=list)
    # credential taint: pointers holding text read from an input field
    tainted: Dict[str, Any] = field(default_factory=dict)
    secrets: Set[str] = field(default_factory=set)  # text typed into a dialog, as logged
    secret_read_rid: Any = None
    last_call: Optional[Dict[str, Any]] = None
    # lure
    icon_source_rids: List[Any] = field(default_factory=list)
    # recon
    recon: Dict[str, Any] = field(default_factory=dict)
    # activation
    activation_rid: Any = None


class IndicatorEngine:
    """Consumes enriched records per process and returns findings as they fire.

    Each indicator fires once per process; `findings()` lists them all at the end.
    """

    def __init__(self) -> None:
        # Keyed by pid + executable, so a reused pid doesn't inherit another process's state
        self._procs: "OrderedDict[Tuple[Any, str], _ProcState]" = OrderedDict()
        self._order: List[Finding] = []

    def findings(self) -> List[Finding]:
        return list(self._order)

    def feed(self, record: Dict[str, Any]) -> List[Finding]:
        ae = record.get("appleEvent") or {}
        pid = record.get("processID")
        key = process_key(record)
        st = self._procs.get(key)
        if st is None:
            st = self._procs[key] = _ProcState()
            st.process = key[1].rsplit("/", 1)[-1]
            if len(self._procs) > MAX_PROCS:
                self._procs.popitem(last=False)
        else:
            self._procs.move_to_end(key)
        out: List[Finding] = []
        if "objc" in ae:
            self._on_call(st, pid, ae["objc"], out)
        elif "objc_result" in ae:
            self._on_result(st, pid, ae["objc_result"], out)
        elif "event" in ae:
            self._on_event(st, pid, ae["event"], out)
        elif ae.get("clone"):
            self._on_command(st, pid, ae["clone"], [], out)
        return out

    # --- helpers ------------------------------------------------------------------

    def _fire(self, st, pid, name, rids, out, detail="") -> None:
        if name in st.fired:
            return
        f = Finding(name, pid, st.process, [r for r in rids if r is not None], detail)
        st.fired[name] = f
        self._order.append(f)
        out.append(f)

    @staticmethod
    def _is_secret(st, value) -> bool:
        """A text argument equal to text typed into a dialog (both cut to the logged prefix)."""
        text = _text(value)
        return bool(text) and any(text[:UTXT_LOGGED_CHARS] == s[:UTXT_LOGGED_CHARS] for s in st.secrets)

    # --- calls ----------------------------------------------------------------------

    def _on_call(self, st, pid, call, out) -> None:
        rid = call.get("return_id")
        sel = call.get("selector") or ""
        kind = call.get("receiver_kind")
        cls = call.get("receiver") if kind == "class" else call.get("receiver_class")
        cls = cls or ""
        args = call.get("args") or []
        _set_capped(st.calls, rid, call)

        if call.get("lookup_failed") and kind == "class":
            self._fire(st, pid, "objc.bridge.failed_lookup", [rid], out, f"{cls}'s {sel}")

        # --- UI
        if kind == "class" and cls.startswith("NSAlert"):
            _append_capped(st.alert_rids, rid)
        if sel == "runModal" and st.alert_rids:
            self._fire(st, pid, "objc.ui.alert", [st.alert_rids[-1], rid], out)
        if sel.startswith("setActivationPol"):
            st.activation_rid = rid
        if sel.startswith("activateIgnoring") and st.activation_rid is not None:
            self._fire(st, pid, "objc.ui.headless_to_gui", [st.activation_rid, rid], out)

        # --- credential prompt
        if kind == "class" and cls.startswith("NSSecureTextFiel"):
            self._fire(st, pid, "objc.cred.secure_field", [rid], out)
        if kind == "class" and cls.startswith(_TEXT_FIELDS):
            _append_capped(st.text_field_rids, rid)
        if sel.startswith("setAccessoryView") and st.text_field_rids:
            st.accessory_rid = rid
            st.prompt_modal_rid = None
            st.prompts += 1
            _append_capped(st.prompt_rids, rid)
            if st.prompts >= 2 and st.failed_check_since_prompt:
                self._fire(
                    st,
                    pid,
                    "objc.cred.reprompt_loop",
                    st.prompt_rids + st.failed_check_rids,
                    out,
                    f"{st.prompts} prompts",
                )
            st.failed_check_since_prompt = False
        if sel == "runModal" and st.accessory_rid is not None:
            st.prompt_modal_rid = rid
        if sel.startswith("stringValue") and st.prompt_modal_rid is not None:
            self._fire(
                st,
                pid,
                "objc.cred.prompt_with_input",
                [st.text_field_rids[-1], st.accessory_rid, st.prompt_modal_rid, rid],
                out,
            )
        if sel.startswith("setLevel_"):
            level = _const(args[0]) if args else None
            if level and level.startswith(_RAISED_LEVELS):
                self._fire(st, pid, "objc.cred.window_raised", [rid], out, level)
        if (kind == "class" and cls.startswith(("ODSession", "ODNode"))) or sel.startswith(
            "verifyPassword_e"
        ):
            self._fire(st, pid, "objc.cred.od_verify", [rid], out)
        if sel.startswith("verifyPassword_e") and st.prompts >= 1:
            # A password check; a prompt shown again after it means it failed. A TRUE
            # result (when results are captured) clears this again.
            st.failed_check_since_prompt = True
            _append_capped(st.failed_check_rids, rid)

        # --- credential handling
        if sel.startswith("writeToFile_atom"):
            recv = call.get("receiver")
            tainted_by = st.tainted.get(recv) if recv else None
            prev = st.last_call or {}
            prev_secret = any(self._is_secret(st, a) for a in prev.get("args") or [])
            if tainted_by is not None or prev_secret:
                self._fire(
                    st,
                    pid,
                    "objc.cred.saved_to_disk",
                    [tainted_by or prev.get("return_id"), rid],
                    out,
                    _text(args[0]) or "" if args else "",
                )
        if sel.startswith("verifyPassword_e"):
            # The password being checked
            st.secrets.update(t for t in map(_text, args[:1]) if t)
        if any(self._is_secret(st, a) for a in args):
            # A typed secret passed on (e.g. NSString's stringWithString:<password>)
            st.secret_read_rid = st.secret_read_rid or rid

        # --- lure
        if sel.startswith(("pathForResource_", "initByReferencin", "initWithContents")):
            _append_capped(st.icon_source_rids, rid)
        if sel.startswith("setIcon_") and st.alert_rids:
            sources = st.icon_source_rids[-2:]
            names = [
                _text(a)
                for r in sources
                for a in (st.calls.get(r) or {}).get("args") or []
                if _text(a)
            ]
            self._fire(st, pid, "objc.lure.app_icon", sources + [rid], out, ", ".join(names))

        # --- network
        if kind == "class" and cls.startswith("NSURL") and sel.startswith("URLWithString_"):
            self._fire(st, pid, "objc.net.url", [rid], out, _text(args[0]) or "" if args else "")
        if (kind == "class" and cls.startswith(_NET_CLASSES)) or sel.startswith(_NET_SELECTORS):
            self._fire(st, pid, "objc.net.session", [rid], out, f"{cls or sel}")
        if (sel.startswith("setHTTPMethod_") and args and _text(args[0]) == "POST") or sel.startswith(
            "setHTTPBody_"
        ):
            self._fire(st, pid, "objc.net.post", [rid], out)

        # --- files / exec
        if sel.startswith(_FILE_STAGE):
            self._fire(st, pid, "objc.file.stage", [rid], out, sel)
        if (
            (kind == "class" and cls.startswith("NSTask"))
            or sel.startswith(("launchedTaskWith", "launchAndReturnE"))
            or (cls.startswith("NSWorkspace") and sel.startswith(("openURL_", "launchApplicati")))
        ):
            self._fire(st, pid, "objc.exec.task", [rid], out)

        # --- recon
        if (kind == "class" and cls.startswith("NSLocale")) or sel.startswith(
            ("countryCode", "localeIdentifier")
        ):
            st.recon.setdefault("locale", rid)
        if kind == "class" and cls.startswith("NSTimeZone") and sel.startswith("systemTimeZone"):
            st.recon.setdefault("timezone", rid)
        arg0 = _text(args[0]) if args else None
        if (sel.startswith("persistentDomain") and arg0 and arg0.startswith("com.apple.HITool")) or (
            sel.startswith("objectForKey_") and arg0 and arg0.startswith("AppleEnabledInpu")
        ):
            st.recon.setdefault("keyboard", rid)
        if len(st.recon) == 3:
            self._fire(st, pid, "objc.recon.region", list(st.recon.values()), out)

        st.last_call = call

    # --- results ----------------------------------------------------------------------

    def _on_result(self, st, pid, result, out) -> None:
        rid = result.get("return_id")
        call = st.calls.get(rid) or {}
        sel = result.get("selector") or ""
        value = result.get("result")
        coerced = result.get("coerced")

        if result.get("error") == "lookup failed" and call.get("receiver_kind") == "class":
            self._fire(
                st, pid, "objc.bridge.failed_lookup", [rid], out,
                f"{call.get('receiver')}'s {sel}",
            )

        if sel.startswith("verifyPassword_e") and "result" in result:
            ok = _first_bool(value)
            if ok is not None:
                self._fire(st, pid, "objc.cred.verify_result", [rid], out, "true" if ok else "false")
                if ok:
                    st.failed_check_since_prompt = False

        if sel.startswith("stringValue") and st.prompt_modal_rid is not None:
            text_value = coerced if coerced is not None else value
            if isinstance(text_value, dict) and text_value.get("type") == "text":
                self._fire(st, pid, "objc.cred.cleartext_leak", [rid], out)
                st.secret_read_rid = rid
                if text_value.get("value"):
                    st.secrets.add(text_value["value"])
            ptr = _ptr(value)
            if ptr:
                _set_capped(st.tainted, ptr, rid)

        # Objects derived from a tainted pointer or from a typed secret stay tainted
        ptr = _ptr(value)
        if ptr and call:
            args = call.get("args") or []
            from_taint = any(_ptr(a) in st.tainted for a in args if _ptr(a)) or (
                call.get("receiver") in st.tainted
            )
            from_secret = any(self._is_secret(st, a) for a in args)
            if (from_taint or from_secret) and ptr not in st.tainted:
                _set_capped(st.tainted, ptr, rid)

    # --- Apple events ---------------------------------------------------------------------

    def _on_event(self, st, pid, event, out) -> None:
        if (event.get("event_class"), event.get("event_id")) == ("syso", "exec"):
            self._on_command(st, pid, event.get("applescript") or "", [event.get("return_id")], out)

    def _on_command(self, st, pid, text, rids, out) -> None:
        if "dscl . -authonly" in text or "dscl -authonly" in text:
            # A shell password check; with a prompt shown, a second prompt means it failed
            if st.prompts >= 1:
                st.failed_check_since_prompt = True
                for r in rids:
                    if r is not None:
                        _append_capped(st.failed_check_rids, r)


def summarize(findings: Iterable[Finding]) -> List[str]:
    lines = []
    for f in findings:
        rids = ", ".join(str(r) for r in f.return_ids)
        detail = f" ({f.detail})" if f.detail else ""
        lines.append(f"{f.name:<28} {f.process}[{f.process_id}] returnIDs: {rids}{detail}")
    return lines
