"""
Event model behind the AEMonitor app: pairs requests with their replies, derives
display fields, flags indicators and filters rows. Pure Python, so it can be
tested without AppKit.
"""

import os
import re
import subprocess
import sys
import threading
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from aemonitor.ast import ANSWER_EVENT
from aemonitor.cli import (
    _build_predicate,
    _iter_ndjson_from_file,
    _iter_ndjson_lines,
    _run_log_show,
    _run_log_stream,
    is_ndjson_path,
)
from aemonitor.indicators import SPECS, IndicatorEngine
from aemonitor.native_stream import NativeStreamUnavailable, iter_live_entries
from aemonitor.objc_correlate import BridgeTracker, is_anchor, is_create, is_result
from aemonitor.unified_logs import (
    PRIVACY_DEFAULT,
    PRIVACY_PRIVATE,
    PRIVACY_PUBLIC,
    enrich_unified_log,
    payload_privacy,
)

FACETS = ("indicator", "process", "target", "code")

# Logging configurations the view can simulate, and the payload privacy classes
# (see payload_privacy) each one reveals. None means no formatString to judge
# from (files from elsewhere, tests); such records are always shown.
PRIVACY_MODES = {
    "private": {None, PRIVACY_PUBLIC, PRIVACY_DEFAULT, PRIVACY_PRIVATE},  # Enable-Private-Data
    "default": {None, PRIVACY_PUBLIC},  # stock macOS
    "public": {None, PRIVACY_PUBLIC, PRIVACY_DEFAULT},  # Default-Privacy-Setting: Public
}
# Most visible first; None (no formatString to judge from) is always shown
_PRIVACY_VISIBILITY = {None: 0, PRIVACY_PUBLIC: 1, PRIVACY_DEFAULT: 2, PRIVACY_PRIVATE: 3}
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "": 0}
_ERRN = re.compile(r"errn=(-?\d+)")
# "Reply of SendToSelf ( err == -1708)": the send itself failed, often with an empty reply
_SEND_ERR = re.compile(r"\berr == (-?\d+)")
_SHELL_STAGING = re.compile(
    r"\b(curl|wget)\b|base64 (-d|--decode)|chmod \+x|xattr -[cdr]|ditto -c|zip -r"
)


@dataclass(frozen=True)
class Indicator:
    id: str
    severity: str
    label: str
    tactic: str
    test: Callable[["Row"], bool] = field(compare=False, repr=False)


# Heuristic indicators. Shell text in events is truncated to 16 chars by the log, so
# shell-content rules mostly fire on clone events, which carry the full source.
INDICATORS: List[Indicator] = [
    Indicator("hidden-answer", "high", "Hidden-answer dialog", "Credential Access · T1056.002",
              lambda r: r.code == "syso,dlog" and ("hidden answer" in r.script or "htxt=" in r.raw)),
    Indicator("keystrokes", "high", "Synthetic keystrokes", "Execution · T1059.002",
              lambda r: r.code in ("prcs,kprs", "prcs,kcod")),
    Indicator("browser-js", "high", "JavaScript in browser", "Collection · T1185",
              lambda r: re.search(r"do JavaScript|execute\b.*\bjavascript", r.script, re.I) is not None),
    Indicator("shell-staging", "high", "Download / staging in shell", "Command and Control · T1105",
              lambda r: (r.code == "syso,exec" or r.kind == "clone")
              and _SHELL_STAGING.search(r.script + "\n" + r.raw) is not None),
    Indicator("shell", "medium", "Shell command", "Execution · T1059.004",
              lambda r: r.code == "syso,exec"),
    Indicator("clipboard", "medium", "Clipboard read", "Collection · T1115",
              lambda r: r.code == "Jons,gClp"),
    Indicator("finder-copy", "medium", "Finder copy / move", "Collection · T1005",
              lambda r: r.target == "Finder" and r.code in ("core,clon", "core,move")),
    Indicator("volume", "medium", "Sets volume", "Defense Evasion",
              lambda r: r.code == "aevt,stvl"),
    Indicator("tcc-denied", "medium", "Automation denied (TCC)", "Discovery",
              lambda r: r.reply_error == "-1743"),
    Indicator("dialog", "low", "Dialog shown", "",
              lambda r: r.code == "syso,dlog"),
    Indicator("finder-delete", "low", "Finder delete", "Defense Evasion · T1070.004",
              lambda r: r.target == "Finder" and r.code == "core,delo"),
]


# AppleScriptObjC bridge-call indicators (aemonitor.indicators) fire per process on the
# record that completed them; they flag the row holding that record
_OBJC_SEVERITY = {
    "objc.cred.prompt_with_input": "high",
    "objc.cred.cleartext_leak": "high",
    "objc.cred.saved_to_disk": "high",
    "objc.cred.reprompt_loop": "high",
    "objc.cred.verify_result": "high",
    "objc.cred.od_verify": "high",
    "objc.lure.app_icon": "high",
    "objc.cred.secure_field": "medium",
    "objc.cred.window_raised": "medium",
    "objc.net.session": "medium",
    "objc.net.post": "medium",
    "objc.file.stage": "medium",
    "objc.exec.task": "medium",
    "objc.recon.region": "medium",
    "objc.bridge.failed_lookup": "low",
    "objc.ui.alert": "low",
    "objc.ui.headless_to_gui": "low",
    "objc.net.url": "low",
}


def _finding_test(name: str) -> Callable[["Row"], bool]:
    return lambda r: name in r.finding_ids


INDICATORS += [
    Indicator(name, _OBJC_SEVERITY.get(name, "low"), spec.description, "AppleScriptObjC",
              _finding_test(name))
    for name, spec in SPECS.items()
]
INDICATORS_BY_ID = {i.id: i for i in INDICATORS}


_AS_KEYWORDS = (
    "tell", "to", "of", "in", "set", "get", "copy", "return", "if", "then", "else", "end",
    "repeat", "while", "times", "try", "on error", "error", "on", "every", "whose", "where",
    "with", "without", "and", "or", "not", "is", "contains", "as", "the", "my", "its", "it",
    "me", "true", "false", "missing value", "application", "given", "from", "by", "thru",
    "through", "first", "last", "some", "script", "property", "global", "local",
)
_AS_COMMANDS = (
    "do shell script", "display dialog", "display alert", "display notification",
    "default answer", "hidden answer", "giving up after", "buttons", "default button",
    "choose file", "choose folder", "choose from list", "the clipboard", "set the clipboard to",
    "keystroke", "key code", "system info", "system attribute", "path to", "current date",
    "run script", "do JavaScript", "do script", "activate", "quit", "open", "duplicate", "move", "delete",
    "count", "exists", "make", "say", "beep", "delay", "random number", "get volume settings",
    "set volume", "administrator privileges",
)


def _phrase_alternation(phrases) -> str:
    # Longest first so "do shell script" wins over "do"; any run of spaces between words
    return "|".join(re.escape(p).replace(r"\ ", r"\s+") for p in sorted(phrases, key=len, reverse=True))


_AS_TOKEN = re.compile(
    r'(?P<string>"(?:[^"\\]|\\.)*"?)'
    r"|(?P<comment>--[^\n]*|\(\*.*?\*\))"
    r"|(?P<label>\b[A-Za-z]\w*(?=:))"
    rf"|(?P<command>\b(?:{_phrase_alternation(_AS_COMMANDS)})\b)"
    rf"|(?P<keyword>\b(?:{_phrase_alternation(_AS_KEYWORDS)})\b)"
    r"|(?P<number>(?<![\w.])-?\d+(?:\.\d+)?\b)",
    re.IGNORECASE | re.DOTALL,
)


def applescript_tokens(text: str) -> List[Tuple[int, int, str]]:
    """(start, end, kind) spans for basic AppleScript highlighting. Kinds: string,
    comment, label (record field), command, keyword, number. Unmatched text is plain."""
    return [(m.start(), m.end(), m.lastgroup) for m in _AS_TOKEN.finditer(text)]


def process_name(path: str) -> str:
    """App name for .app bundles, otherwise the executable name."""
    if not path:
        return "unknown"
    if ".app/" in path:
        return os.path.basename(path.split(".app/", 1)[0])
    return os.path.basename(path)


def reply_summary(
    reply: Optional[Dict[str, Any]], event_message: str = ""
) -> Tuple[str, Optional[str]]:
    """(display text, error number or None) for a reply part of appleEvent."""
    if not reply:
        return "", None
    text = re.sub(r"^aevtansr\s*", "", reply.get("applescript") or "")
    m = _ERRN.search(reply.get("raw") or "") or _SEND_ERR.search(event_message)
    err = m.group(1) if m and m.group(1) != "0" else None
    if err:
        return f"error {err}" + (f": {text}" if text else ""), err
    return text, None


@dataclass(eq=False)
class Row:
    """One table row: a request with its reply attached, a lone reply, or a clone."""

    id: int
    request: Optional[Dict[str, Any]]
    reply: Optional[Dict[str, Any]]
    kind: str = "event"
    target: str = ""
    code: str = ""
    script: str = ""
    reply_text: str = ""
    reply_error: Optional[str] = None
    raw: str = ""
    flags: List[Indicator] = field(default_factory=list)
    severity: str = ""
    search_text: str = ""
    # Bridge calls: result records (a return value, then maybe its `as text` coercion)
    results: List[Dict[str, Any]] = field(default_factory=list)
    finding_ids: Set[str] = field(default_factory=set)

    @property
    def base(self) -> Dict[str, Any]:
        return self.request or self.reply  # type: ignore[return-value]

    @property
    def timestamp(self) -> str:
        return self.base.get("timestamp") or ""

    @property
    def pid(self) -> Any:
        return self.base.get("processID", "")

    @property
    def process_path(self) -> str:
        return self.base.get("processImagePath") or ""

    @property
    def process(self) -> str:
        return process_name(self.process_path)

    @property
    def thread_id(self) -> Any:
        return self.base.get("threadID")

    @property
    def return_id(self) -> Any:
        part = self.event_part or self.reply_part or self.objc_part or {}
        return part.get("return_id")

    @property
    def privacy(self) -> Optional[str]:
        """Logging privacy of the record carrying this row's content (the request,
        or the lone reply/clone); see payload_privacy."""
        if self.kind == "objc" and self.request is not None and "objc" not in self.request["appleEvent"]:
            # Results whose call row is gone (evicted). A result is only ever paired
            # because its call was seen in a src=%{private}s clone, so it is as hidden
            # as that call; a failed-lookup error comes from its own event= line.
            first = self.request["appleEvent"]["objc_result"]
            return self.request.get("privacy") if first.get("error") else PRIVACY_PRIVATE
        if self.kind == "objc" and self.request is not None:
            # A bridge call is a src=%{private}s clone, and its results mean nothing
            # without it. A failed lookup is also logged on its own as a public
            # event= line, so the row is as visible as the most visible of the two.
            standalone = [self.request] + [
                r for r in self.results if r["appleEvent"]["objc_result"].get("error")
            ] + ([self.reply] if self.reply is not None else [])
            return min((r.get("privacy") for r in standalone), key=_PRIVACY_VISIBILITY.get)
        return self.base.get("privacy")

    @property
    def correlation(self) -> Optional[Tuple[Any, Any]]:
        """Key linking a request to its reply: (threadID, returnID), or None if unknown."""
        rid, tid = self.return_id, self.thread_id
        return (tid, rid) if rid is not None and tid is not None else None

    @property
    def event_part(self) -> Optional[Dict[str, Any]]:
        return self.request["appleEvent"].get("event") if self.request else None

    @property
    def reply_part(self) -> Optional[Dict[str, Any]]:
        return self.reply["appleEvent"].get("reply") if self.reply else None

    @property
    def objc_part(self) -> Optional[Dict[str, Any]]:
        """The bridge call, or the first result when the call itself wasn't seen."""
        ae = self.base["appleEvent"]
        return ae.get("objc") or ae.get("objc_result")

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return [f for r in self.records() for f in r.get("findings") or []]

    def records(self) -> List[Dict[str, Any]]:
        """Distinct log records behind this row, request first."""
        if self.results:
            return (
                ([self.request] if self.request is not None else [])
                + self.results
                + ([self.reply] if self.reply is not None else [])
            )
        if self.request is not None and self.reply is not None and self.request is not self.reply:
            return [self.request, self.reply]
        return [self.base]

    def facet_value(self, facet: str) -> str:
        return {"process": self.process, "target": self.target, "code": self.code}.get(facet, "")

    def derive(self) -> None:
        ae = self.base["appleEvent"]
        self.finding_ids = {f["indicator"] for f in self.findings}
        if "objc" in ae or "objc_result" in ae:
            self._derive_objc()
            return
        if ae.get("clone") is not None:
            self.kind, self.code, self.script = "clone", "clone", ae["clone"]
        elif self.event_part:
            ev = self.event_part
            self.kind = "event"
            self.target = ev.get("target") or ""
            self.code = f"{ev['event_class']},{ev['event_id']}" if ev.get("event_class") else ""
            self.script = ev.get("applescript") or ""
        else:
            self.kind = "reply"
        self.reply_text, self.reply_error = reply_summary(
            self.reply_part, (self.reply or {}).get("eventMessage") or ""
        )
        self.raw = "\n".join(
            p.get("raw") or "" for p in (self.event_part, self.reply_part) if p
        )
        self._derive_flags()

    def _derive_objc(self) -> None:
        call = (self.request or {}).get("appleEvent", {}).get("objc") or {}
        results = [r["appleEvent"]["objc_result"] for r in self.results]
        if not call and self.request is not None:
            results.insert(0, self.request["appleEvent"]["objc_result"])
        self.kind, self.code = "objc", "objc"
        receiver = call.get("receiver") if call.get("receiver_kind") == "class" else call.get("receiver_class")
        self.target = receiver or ""
        self.script = call.get("applescript") or (results[0].get("call") if results else "") or ""
        shown = [r["applescript"] for r in results if not r.get("void") and r.get("applescript")]
        self.reply_text = "; ".join(shown)
        errors = [r["error"] for r in results if r.get("error")]
        self.reply_error = errors[0] if errors else None
        self.raw = call.get("raw") or ""
        self._derive_flags()

    def _derive_flags(self) -> None:
        self.flags = [i for i in INDICATORS if i.test(self)]
        self.severity = max((f.severity for f in self.flags), key=_SEVERITY_RANK.get, default="")
        self.search_text = "\n".join(
            [self.process, self.target, self.code, self.script, self.reply_text, self.raw]
        ).lower()


# Housekeeping events never shown: ascr,gdut is the scripting runtime loading its
# built-in terminology (sent to itself before a script runs, usually failing with -1708)
HIDDEN_EVENT_CODES = {("ascr", "gdut")}


class RecordPreparer:
    """Turns raw unified log entries into enriched records, dropping noise.

    Stateful (repeated clones, and replies to hidden events, are dropped; bridge calls
    are paired with their results and indicators tracked per process), so use one per
    source. Records that complete a bridge-call indicator carry it under "findings".
    """

    def __init__(self) -> None:
        self._last_clone: Optional[str] = None
        self._hidden: "OrderedDict[Tuple[Any, Any], None]" = OrderedDict()
        self._tracker = BridgeTracker()
        self._engine = IndicatorEngine()

    def __call__(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        record = self._prepare(entry)
        if record is not None:
            findings = self._engine.feed(record)
            if findings:
                record["findings"] = [f.to_dict() for f in findings]
        return record

    def _prepare(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        message = entry.get("eventMessage")
        if message is None:
            return None
        entry.setdefault("processImagePath", "")
        if is_create(message) or is_anchor(message) or is_result(message):
            # Lines that only matter for pairing bridge calls with their results
            return self._tracker.on_line(entry)
        try:
            record = enrich_unified_log(entry)
        except Exception:
            return None
        if record is None:
            return None
        record["privacy"] = payload_privacy(record.get("formatString") or "")
        # Same as the ndjson output: drop parts that failed to parse
        ae = record["appleEvent"] = {k: v for k, v in record["appleEvent"].items() if v is not None}
        if not ae:
            return None
        if "objc" in ae:
            # A bridge call, or (for a failed class lookup) the result of one
            return self._tracker.on_call(record)
        event = ae.get("event")
        if (
            event is not None
            and "reply" not in ae
            and (event.get("event_class"), event.get("event_id")) == ANSWER_EVENT
        ):
            # aevt,ansr is an answer; the AE framework sometimes logs it via event={...}.
            # Treat it as a reply so it pairs with its request instead of showing as a row.
            ae["reply"] = ae.pop("event")
        if "clone" in record["appleEvent"]:
            # Clones repeat and short ones are noise (same filter as the syslog output)
            clone = record["appleEvent"]["clone"]
            if clone is None or len(clone) <= 16 or clone == self._last_clone:
                return None
            self._last_clone = clone
        if self._is_hidden(record):
            return None
        return record

    def _is_hidden(self, record: Dict[str, Any]) -> bool:
        ae = record["appleEvent"]
        event = ae.get("event")
        if event is not None:
            if (event.get("event_class"), event.get("event_id")) not in HIDDEN_EVENT_CODES:
                return False
            if "reply" not in ae:
                # Remember the request so its separately logged reply is dropped too
                self._hidden[(record.get("processID"), event.get("return_id"))] = None
                if len(self._hidden) > 1000:
                    self._hidden.popitem(last=False)
            return True
        reply = ae.get("reply")
        if reply is None:
            return False
        key = (record.get("processID"), reply.get("return_id"))
        if key not in self._hidden:
            return False
        del self._hidden[key]
        return True


class EventStore:
    """Holds rows in arrival order and pairs replies with their requests by pid + returnID."""

    def __init__(self, pending_limit: int = 5000) -> None:
        self.rows: List[Row] = []
        self.counts: Dict[str, Counter] = {f: Counter() for f in FACETS}
        # Rows per Row.privacy class, kept in step with the rows (see _count)
        self.privacy_counts: Counter = Counter()
        self.private_data_seen = False
        self._pending: "OrderedDict[Tuple[Any, Any], Row]" = OrderedDict()
        self._pending_limit = pending_limit
        # Bridge-call rows by (pid, returnID): results keep arriving after the first
        self._objc: "OrderedDict[Tuple[Any, Any], Row]" = OrderedDict()
        self._next_id = 1

    def add(self, record: Dict[str, Any]) -> Tuple[Row, bool]:
        """Add an enriched record. Returns (row, is_new); is_new is False when a reply
        was attached to an existing row."""
        if "<private>" in (record.get("eventMessage") or ""):
            self.private_data_seen = True
        ae = record["appleEvent"]
        if "objc" in ae:
            row = self._append(record, None)
            self._objc[self._key(record, ae["objc"])] = row
            if len(self._objc) > self._pending_limit:
                self._objc.popitem(last=False)
            return row, True
        if "objc_result" in ae:
            row = self._objc.get(self._key(record, ae["objc_result"]))
            if row is None:
                return self._append(record, None), True
            self._count(row, -1)
            row.results.append(record)
            row.derive()
            self._count(row, 1)
            return row, False
        if "reply" in ae and "event" not in ae:
            # A reply logged by the sender: attach it to the request it answers
            key = self._key(record, ae["reply"])
            row = self._pending.pop(key, None)
            if row is None and key in self._objc and self._objc[key].reply is None:
                # A failed bridge-call lookup is answered by a real reply (-1708)
                row = self._objc[key]
            if row is not None:
                self._count(row, -1)
                row.reply = record
                row.derive()
                self._count(row, 1)
                return row, False
            return self._append(None, record), True

        # Event and reply in one message (logged by the receiver), a bare request, or a clone
        row = self._append(record, record if "reply" in ae else None)
        if "event" in ae and "reply" not in ae:
            self._pending[self._key(record, ae["event"])] = row
            if len(self._pending) > self._pending_limit:
                self._pending.popitem(last=False)
        return row, True

    def clear(self) -> None:
        self.rows.clear()
        self._pending.clear()
        self._objc.clear()
        self.privacy_counts.clear()
        for c in self.counts.values():
            c.clear()

    def hidden_by(self, revealed: Set[Optional[str]]) -> int:
        """How many rows a logging configuration revealing these classes would not record."""
        return sum(n for cls, n in self.privacy_counts.items() if cls not in revealed)

    @staticmethod
    def _key(record: Dict[str, Any], part: Dict[str, Any]) -> Tuple[Any, Any]:
        return record.get("processID"), part.get("return_id")

    def _append(self, request: Optional[Dict[str, Any]], reply: Optional[Dict[str, Any]]) -> Row:
        row = Row(self._next_id, request, reply)
        self._next_id += 1
        row.derive()
        self.rows.append(row)
        self._count(row, 1)
        return row

    def _count(self, row: Row, delta: int) -> None:
        # Called with -1 before a row changes and +1 after, so privacy stays in step
        self.privacy_counts[row.privacy] += delta
        for facet in ("process", "target", "code"):
            value = row.facet_value(facet)
            if value:
                self.counts[facet][value] += delta
        for f in row.flags:
            self.counts["indicator"][f.id] += delta
        for c in self.counts.values():
            for key in [k for k, n in c.items() if n <= 0]:
                del c[key]


_QUERY_KEYS = ("pid", "proc", "target", "code", "flag")


@dataclass
class RowFilter:
    """Search text plus sidebar selections and mutes."""

    query: str = ""
    only_flagged: bool = False
    show_clones: bool = True
    privacy_mode: str = "private"  # key of PRIVACY_MODES
    include: Dict[str, Set[str]] = field(default_factory=lambda: {f: set() for f in FACETS})
    muted: Set[Tuple[str, str]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.set_query(self.query)

    def set_query(self, query: str) -> None:
        """Free text, or key:value terms for pid, proc, target, code and flag."""
        self.query = query
        self._terms: Dict[str, List[str]] = {k: [] for k in ("text",) + _QUERY_KEYS}
        for tok in query.split():
            key, sep, value = tok.partition(":")
            if sep and key.lower() in _QUERY_KEYS:
                self._terms[key.lower()].append(value.lower())
            else:
                self._terms["text"].append(tok.lower())

    def matches(self, row: Row) -> bool:
        if not self.show_clones and row.kind == "clone":
            return False
        if row.privacy not in PRIVACY_MODES[self.privacy_mode]:
            return False
        if self.only_flagged and not row.flags:
            return False
        for facet, value in self.muted:
            if row.facet_value(facet) == value:
                return False
        for facet in ("process", "target", "code"):
            wanted = self.include[facet]
            if wanted and row.facet_value(facet) not in wanted:
                return False
        if self.include["indicator"] and not any(f.id in self.include["indicator"] for f in row.flags):
            return False

        t = self._terms
        if t["pid"] and str(row.pid) not in t["pid"]:
            return False
        for key, value in (("proc", row.process), ("target", row.target), ("code", row.code)):
            if t[key] and not any(q in value.lower() for q in t[key]):
                return False
        if t["flag"] and not any(q in f.id or q == f.severity for q in t["flag"] for f in row.flags):
            return False
        return all(q in row.search_text for q in t["text"])


class Monitor:
    """Runs one event source (live stream or file) on a background thread and queues
    prepared records for the UI thread to drain."""

    def __init__(self) -> None:
        self.source = ""
        self.backend = ""
        self.exit_code: Optional[int] = None
        self._lock = threading.Lock()
        self._records: List[Dict[str, Any]] = []
        self._thread: Optional[threading.Thread] = None
        self._stop: Optional[threading.Event] = None
        self._proc: Optional[subprocess.Popen] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, archive_path: Optional[str] = None) -> None:
        """Stream live (no path) or read a .logarchive / .ndjson file."""
        self.stop()
        with self._lock:
            # Records the previous source queued but the UI hasn't drained yet
            self._records = []
        stop = threading.Event()
        proc: Optional[subprocess.Popen] = None
        if archive_path and is_ndjson_path(archive_path):
            entries = _iter_ndjson_from_file(archive_path)
        elif archive_path:
            proc = _run_log_show(archive_path, _build_predicate(None, objc_results=True))
            entries = _iter_ndjson_lines(proc)
        else:
            try:
                entries = iter_live_entries(_build_predicate(None, objc_results=True), stop)
            except NativeStreamUnavailable as e:
                print(f"aemonitor: native backend unavailable ({e}), using log stream", file=sys.stderr)
                proc = _run_log_stream(_build_predicate(None, objc_results=True))
                entries = _iter_ndjson_lines(proc)
        self._stop, self._proc = stop, proc
        self.source = archive_path or ""
        self.backend = "" if archive_path else ("log" if proc is not None else "native")
        self.exit_code = None
        self._thread = threading.Thread(
            target=self._run, args=(entries, proc, stop), daemon=True, name="aemonitor-monitor"
        )
        self._thread.start()

    def stop(self) -> None:
        if self._stop is not None:
            self._stop.set()
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
        if self._thread is not None:
            # A native stream notices the stop flag within its 0.5 s poll
            self._thread.join(timeout=2)

    def drain(self) -> List[Dict[str, Any]]:
        with self._lock:
            records, self._records = self._records, []
        return records

    def _run(self, entries, proc: Optional[subprocess.Popen], stop: threading.Event) -> None:
        prepare = RecordPreparer()
        try:
            for entry in entries:
                if stop.is_set():
                    break
                record = prepare(entry)
                if record is not None:
                    with self._lock:
                        # stop() only waits 2 s; a run still finishing after a new
                        # source started must not add to the new source's events
                        if stop.is_set():
                            break
                        self._records.append(record)
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait()
                if not stop.is_set():
                    self.exit_code = proc.returncode
