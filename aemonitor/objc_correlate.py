"""
Stateful tracking of AppleScriptObjC bridge calls: object names and return values.

There is no reply event for a bridge call. AppleScript reads the result back on the
same thread once the call returns, and the AE framework logs that read:

    cloneForCompatability(src={ascr,psbr ...})            <- the call
    ... (----) as **** = [<args>] err=0/noErr               <- argument echo, ignored
    AEGetParamDesc for keyword errn type long               <- anchor: call returned
    OSErr AEGetParamDesc(...)(----) as **** = <result> ...  <- the result

So the result is the first `(----) as **** =` line after an `errn` anchor on the
same (processID, threadID). Calls can nest (a delegate handler fired inside
`runUntilDate_`), so each thread keeps a stack.

Other Apple events the script runtime creates on the thread (`do shell script`,
`core,getd` to evaluate an expression, ...) have their result read the same way.
Each `AECreateAppleEvent(...)` line pushes a frame for them so their results are
not mistaken for a bridge call's; those results are discarded, except:

When a call returns an object and the very next event is a `core,getd` (the script
coercing it, `... as text`), its result is attached to the call as `coerced`. That
is where a password typed into a dialog appears in cleartext.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from aemonitor.objc import parse_result_value, render_call, render_value

ANCHOR_MARKER = "AEGetParamDesc for keyword errn type long"
RESULT_MARKER = "(----) as **** = "
CREATE_MARKER = "AECreateAppleEvent("
_CREATE_RE = re.compile(r"AppleEvent \*\)\((.{4}),(.{4}) target=")
_RESULT_RE = re.compile(r"\(----\) as \*\*\*\* = (.*) err=(-?\d+)(?:/\S*)?\s*$", re.DOTALL)

# errAEDescNotFound: the call returned nothing (void)
ERR_DESC_NOT_FOUND = -1701

MAX_STACK = 64
MAX_SEEN = 1024
# Processes and threads tracked at once; the least recently active are forgotten so a
# long live session doesn't grow without bound
MAX_PROCS = 256
MAX_THREADS = 1024

TEXT_FIELD_CLASSES = ("NSTextField", "NSSecureTextFiel")
SECURE_FIELD_CLASS = "NSSecureTextFiel"

# Class prefixes stripped when naming objects (NSAlert -> alert1)
_CLASS_PREFIXES = ("NS", "OD", "CF", "CG", "CI", "AV", "WK", "UN", "SC", "MK", "CL", "UT")
_NAME_STOP_WORDS = ("With", "For", "At", "By", "From", "Of", "In", "To", "Using", "And")


def is_anchor(message: str) -> bool:
    return ANCHOR_MARKER in message


def is_result(message: str) -> bool:
    return RESULT_MARKER in message


def is_create(message: str) -> bool:
    return CREATE_MARKER in message


def _lower_camel(name: str) -> str:
    k = 0
    while k < len(name) and name[k].isupper():
        k += 1
    if k == 0:
        return name
    if k == len(name):
        return name.lower()
    if k == 1:
        return name[0].lower() + name[1:]
    return name[: k - 1].lower() + name[k - 1 :]


def class_base_name(cls: str) -> str:
    for prefix in _CLASS_PREFIXES:
        if cls.startswith(prefix) and len(cls) > len(prefix) and cls[len(prefix)].isupper():
            cls = cls[len(prefix) :]
            break
    return _lower_camel(cls) or "obj"


def selector_base_name(sel: str) -> str:
    head = sel.split("_", 1)[0]
    for i in range(1, len(head)):
        if head[i].isupper() and head[i - 1].islower():
            if any(head.startswith(w, i) for w in _NAME_STOP_WORDS):
                head = head[:i]
                break
    return head or "obj"


def process_key(entry: Dict[str, Any]) -> Tuple[Any, str]:
    """A process: its pid plus its executable, so state never carries over to an
    unrelated process that later reuses the pid."""
    return (
        entry.get("processID") or entry.get("processIdentifier"),
        entry.get("processImagePath") or "",
    )


def _thread_key(entry: Dict[str, Any]) -> Tuple[Tuple[Any, str], Any]:
    return (process_key(entry), entry.get("threadID") or entry.get("threadIdentifier"))


class _Frame:
    __slots__ = ("kind", "call", "armed")

    def __init__(self, kind: str, call: Optional[Dict[str, Any]]) -> None:
        # "call": bridge call; "coerce": core,getd on a call's result; "ae": anything else
        self.kind = kind
        self.call = call
        self.armed = False


class _Process:
    def __init__(self) -> None:
        self.aliases: Dict[str, str] = {}
        self.classes: Dict[str, str] = {}  # ptr -> class that created it
        self.counters: Dict[str, int] = {}
        self.ran_modal = False

    def name(self, ptr: str) -> str:
        if ptr not in self.aliases:
            self.aliases[ptr] = self._next("obj")
        return self.aliases[ptr]

    def assign(self, ptr: str, base: str) -> None:
        self.aliases[ptr] = self._next(base)

    def _next(self, base: str) -> str:
        n = self.counters.get(base, 0) + 1
        self.counters[base] = n
        return f"{base}{n}"


class BridgeTracker:
    """Names objects, attaches return values to bridge calls and flags typed text reads.

    Feed every log entry to `feed()`, enriched or not, in log order. It returns
    records to output: the (decorated) bridge call, an `objc_result` record, or
    nothing. Calls are returned as soon as they are seen, so a stream never waits
    on a result.
    """

    def __init__(self) -> None:
        # Keyed by process_key(); "pid" below always means that key
        self._procs: "OrderedDict[Any, _Process]" = OrderedDict()
        self._stacks: "OrderedDict[Tuple[Any, Any], List[_Frame]]" = OrderedDict()
        # (process, tid) -> (call, result) for the last popped call that returned an object
        self._last_pop: Dict[Tuple[Any, Any], Tuple[Dict[str, Any], Any]] = {}
        self._seen: "OrderedDict[Tuple[Any, Any], Dict[str, Any]]" = OrderedDict()

    # --- public ---------------------------------------------------------------

    def proc(self, pid: Any) -> _Process:
        proc = self._procs.get(pid)
        if proc is None:
            proc = self._procs[pid] = _Process()
            if len(self._procs) > MAX_PROCS:
                self._procs.popitem(last=False)
        else:
            self._procs.move_to_end(pid)
        return proc

    def namer(self, pid: Any):
        return self.proc(pid).name

    def on_call(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle an enriched entry carrying appleEvent.objc. Returns it, or None if a repeat."""
        objc = entry["appleEvent"]["objc"]
        key = _thread_key(entry)
        pid = key[0]
        seen_key = (pid, objc.get("return_id"))

        if objc.get("lookup_failed"):
            # The real-event fallback of a call already logged as a clone: report the
            # failure against that call instead of a second call
            original = self._seen.get(seen_key)
            if original is not None:
                self._drop_frame(key, original)
                original["lookup_failed"] = True
                return self._result_record(entry, original, None, error="lookup failed")
            self._remember(seen_key, objc)
            self._decorate(pid, objc)
            return entry

        if seen_key in self._seen:
            return None  # the same call logged twice (seen on failed lookups)
        self._remember(seen_key, objc)
        self._push(key, _Frame("call", objc))
        self._decorate(pid, objc)
        if objc["selector"] == "runModal" and not objc.get("selector_truncated"):
            self.proc(pid).ran_modal = True
        return entry

    def on_line(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle a raw line: an event creation, an errn anchor or a `(----)` result."""
        if (entry.get("appleEvent") or {}).get("objc_result") is not None:
            # Already paired, e.g. re-reading an AEMonitor export: the anchor and
            # event-creation lines that paired it aren't in the file, so keep it as is
            return entry
        message = entry.get("eventMessage") or ""
        key = _thread_key(entry)
        if is_create(message):
            self._on_create(key, message)
            return None
        if is_anchor(message):
            self._on_anchor(key)
            return None
        if is_result(message):
            return self._on_result(entry, key, message)
        return None

    # --- stack ------------------------------------------------------------------

    def _remember(self, seen_key, objc) -> None:
        self._seen[seen_key] = objc
        if len(self._seen) > MAX_SEEN:
            self._seen.popitem(last=False)

    def _push(self, key, frame: _Frame) -> None:
        stack = self._stacks.get(key)
        if stack is None:
            stack = self._stacks[key] = []
            if len(self._stacks) > MAX_THREADS:
                old, _ = self._stacks.popitem(last=False)
                self._last_pop.pop(old, None)
        else:
            self._stacks.move_to_end(key)
        # A frame that returned but whose result never came (an error) is done
        while stack and stack[-1].armed:
            stack.pop()
        stack.append(frame)
        if len(stack) > MAX_STACK:
            del stack[0]
        self._last_pop.pop(key, None)

    def _drop_frame(self, key, call) -> None:
        stack = self._stacks.get(key, [])
        for i in range(len(stack) - 1, -1, -1):
            if stack[i].call is call:
                del stack[i]
                return

    def _on_create(self, key, message) -> None:
        m = _CREATE_RE.search(message)
        if not m:
            return
        code = (m.group(1), m.group(2))
        if code == ("aevt", "ansr"):
            return  # a reply being built
        if code == ("ascr", "psbr"):
            # target=NULL-impl: an outgoing bridge call, tracked from its clone line.
            # Otherwise ObjC calling back into a script handler: no result to pair.
            return
        last = self._last_pop.get(key)
        if code == ("core", "getd") and last is not None:
            # Evaluating the object a call just returned: `... as text`
            self._push(key, _Frame("coerce", last[0]))
        else:
            self._push(key, _Frame("ae", None))

    def _on_anchor(self, key) -> None:
        stack = self._stacks.get(key)
        if stack and not stack[-1].armed:
            stack[-1].armed = True

    def _on_result(self, entry, key, message) -> Optional[Dict[str, Any]]:
        stack = self._stacks.get(key)
        if not (stack and stack[-1].armed):
            return None  # argument echo, or a stream that started mid-call
        m = _RESULT_RE.search(message)
        if not m:
            return None
        text, err = m.group(1), int(m.group(2))
        void = err == ERR_DESC_NOT_FOUND
        try:
            value = None if void else parse_result_value(text)
        except Exception:
            value = {"type": "raw", "value": text}

        frame = stack.pop()
        if frame.kind == "coerce":
            return self._coerced_record(entry, key, frame.call, value)
        if frame.kind != "call":
            return None
        call = frame.call
        pid = key[0]
        self._learn_from_result(pid, call, value)
        if isinstance(value, dict) and value.get("type") == "object":
            self._last_pop[key] = (call, value)
        return self._result_record(entry, call, value, void=void)

    # --- naming and typed text -----------------------------------------------------

    def _decorate(self, pid, objc: Dict[str, Any]) -> None:
        proc = self.proc(pid)
        if objc["receiver_kind"] == "instance" and objc.get("receiver"):
            cls = proc.classes.get(objc["receiver"])
            if cls:
                objc["receiver_class"] = cls
        objc["applescript"] = render_call(objc, proc.name)

    def _learn_from_result(self, pid, call, value) -> None:
        if isinstance(value, list):
            # Methods called with an error:(reference) out-parameter return
            # {result, error}
            has_ref = any(isinstance(a, dict) and a.get("type") == "reference" for a in call["args"])
            for i, item in enumerate(value):
                if i and has_ref:
                    self._name_object(pid, call, item, "error")
                else:
                    self._name_object(pid, call, item)
            return
        self._name_object(pid, call, value)

    def _name_object(self, pid, call, value, base: Optional[str] = None) -> None:
        if not (isinstance(value, dict) and value.get("type") == "object" and value.get("ptr")):
            return
        proc = self.proc(pid)
        ptr = value["ptr"]
        sel = call["selector"]
        kind = call["receiver_kind"]
        if base is not None:
            if ptr not in proc.aliases:
                proc.assign(ptr, base)
        elif kind == "class":
            cls = call["receiver"]
            if sel == "alloc" or ptr not in proc.aliases:
                proc.classes[ptr] = cls
                proc.assign(ptr, class_base_name(cls))
        elif kind == "function":
            if ptr not in proc.aliases:
                proc.assign(ptr, class_base_name(sel))  # NSUserName() -> userName1
        elif kind == "instance":
            if ptr == call.get("receiver"):
                return  # init..., returns self
            if ptr not in proc.aliases:
                proc.assign(ptr, selector_base_name(sel))

    def _is_typed_secret(self, pid, call) -> bool:
        """A stringValue read from a text field after a dialog ran."""
        if not call["selector"].startswith("stringValue"):
            return False
        cls = call.get("receiver_class") or self.proc(pid).classes.get(call.get("receiver"))
        if cls is not None:
            return cls.startswith(TEXT_FIELD_CLASSES)
        return self.proc(pid).ran_modal

    def _maybe_secret(self, pid, call, value) -> None:
        if (
            isinstance(value, dict)
            and value.get("type") == "text"
            and self._is_typed_secret(pid, call)
        ):
            call["secret_read"] = True

    # --- records ------------------------------------------------------------------

    def _base(self, entry) -> Dict[str, Any]:
        keep = (
            "timestamp",
            "processID",
            "threadID",
            "activityIdentifier",
            "processImagePath",
            "subsystem",
            "category",
            "messageType",
            "eventMessage",
            "formatString",
        )
        # "privacy" is set by the app on the entries it enriches (a failed lookup's
        # event= line); result lines aren't enriched and don't carry it
        keep += ("privacy",)
        return {k: entry[k] for k in keep if k in entry}

    def _result_record(self, entry, call, value, *, void=False, error=None):
        pid = _thread_key(entry)[0]
        self._maybe_secret(pid, call, value)
        result = {
            "return_id": call.get("return_id"),
            "selector": call["selector"],
            "selector_truncated": call.get("selector_truncated", False),
            "call": call.get("applescript"),
            "result": value,
            "void": void,
        }
        if error:
            result["error"] = error
            result["applescript"] = f"error: {error}"
        else:
            result["applescript"] = (
                "(no result)" if void else render_value(value, self.proc(pid).name)
            )
        if call.get("secret_read"):
            result["secret_read"] = True
        record = self._base(entry)
        record["appleEvent"] = {"objc_result": result}
        return record

    def _coerced_record(self, entry, key, call, value):
        pid = key[0]
        self._maybe_secret(pid, call, value)
        call["coerced"] = value
        result = {
            "return_id": call.get("return_id"),
            "selector": call["selector"],
            "selector_truncated": call.get("selector_truncated", False),
            "call": call.get("applescript"),
            "coerced": value,
            "applescript": "as text --> " + render_value(value, self.proc(pid).name)
            if isinstance(value, dict) and value.get("type") == "text"
            else "then --> " + render_value(value, self.proc(pid).name),
        }
        if call.get("secret_read"):
            result["secret_read"] = True
        record = self._base(entry)
        record["appleEvent"] = {"objc_result": result}
        return record
