"""
AppleScriptObjC bridge calls.

AppleScriptObjC (`use framework "Foundation"`) sends every Objective-C message, and
every bridged C function call, through an internal `ascr,psbr` ("call subroutine")
Apple event. The AE framework logs it once per call, at debug level, as:

    cloneForCompatability(src={ascr,psbr target='psn '[<host>] {snam=<selector>,
        ----=[<args>]} attr:{subj=<receiver>,me  =<receiver>,csig=65536}
        returnID=<n>} dst=0x...

`src` is logged as %{private}s, so these lines are only readable when private data
logging is enabled for com.apple.appleevents.

This module is stateless: it decodes one call into plain data and renders it as
pseudo-AppleScript. Pointer aliases and return values need state across lines and
live in `aemonitor.objc_correlate`.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from aemonitor.aedebug import decode_utxt_raw, parse_apple_event_debug

BRIDGE_EVENT = ("ascr", "psbr")
BRIDGE_CLONE_MARKER = "cloneForCompatability(src={ascr,psbr"
BRIDGE_EVENT_MARKER = "event={ascr,psbr"

# utxt payloads are logged as <true byte length>/$<first 32 bytes>[...]
UTXT_LOGGED_BYTES = 32
UTXT_LOGGED_CHARS = UTXT_LOGGED_BYTES // 2

# Selector prefixes for C functions are just the function name; selectors for ObjC
# methods use "_" for each ":"
Namer = Callable[[str], str]


def is_bridge_clone(message: str) -> bool:
    return BRIDGE_CLONE_MARKER in message


def is_bridge_event(message: str) -> bool:
    return BRIDGE_EVENT_MARKER in message


def extract_balanced(text: str, start: int) -> Optional[str]:
    """Return the balanced {...} block starting at text[start], or None."""
    if start >= len(text) or text[start] != "{":
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def extract_clone_event(message: str) -> Optional[str]:
    """Return the `{...}` payload of a `cloneForCompatability(src={...} dst=...)` line."""
    marker = "cloneForCompatability(src="
    i = message.find(marker)
    if i == -1:
        return None
    return extract_balanced(message, i + len(marker))


# ----------------------------
# Values
# ----------------------------


def optr_to_ptr(raw: str) -> str:
    """optr(8/$e02bbf0e0b000000) is a little-endian pointer -> '0xb0ebf2be0'."""
    _length, _hex = raw.split("/$", 1)
    data = bytes.fromhex(_hex.strip("."))
    return hex(int.from_bytes(data, "little"))


def decode_utxt(raw: str) -> Dict[str, Any]:
    length_str, _hex = raw.split("/$", 1)
    try:
        length = int(length_str)
    except ValueError:
        length = len(_hex.strip(".")) // 2
    text = decode_utxt_raw(raw)
    return {
        "type": "text",
        "value": text,
        "length": length // 2,
        "truncated": length > UTXT_LOGGED_BYTES,
    }


def _record_ptr(rec: Dict[str, Any]) -> Optional[str]:
    seld = rec.get("seld")
    if isinstance(seld, dict) and seld.get("__type__") == "optr":
        return optr_to_ptr(seld["__raw__"])
    return None


def _is_object_record(v: Any) -> bool:
    return isinstance(v, dict) and v.get("want") == "ocid" and "seld" in v


def _is_constant_record(v: Any) -> bool:
    return isinstance(v, dict) and v.get("want") == "prop" and v.get("form") == "usrp"


def _parse_bracket_inner(inner: str) -> Any:
    """`[15]` is read by the generic parser as a bracket token; re-read it as a list."""
    from aemonitor.aedebug import Parser

    p = Parser(f"[{inner},]")
    return [decode_value(x) for x in p.read_list()]


def decode_value(v: Any) -> Any:
    """Normalise a parsed Apple event debug value into plain JSON-able data.

    Scalars stay scalars (int, float, bool, None). Everything else is a dict with a
    "type": text, object, constant, missing, reference or raw.
    """
    if isinstance(v, bool) or isinstance(v, int) or isinstance(v, float):
        return v
    if isinstance(v, list):
        return [decode_value(x) for x in v]
    if isinstance(v, str):
        if v in ("TRUE", "true"):
            return True
        if v in ("FALSE", "false"):
            return False
        if v == "msng":
            return {"type": "missing"}
        if v == "obj":  # `obj ` with the trailing space eaten: an out-parameter reference
            return {"type": "reference"}
        if v == "NULL-impl":
            return None
        try:
            return float(v)
        except ValueError:
            return {"type": "raw", "value": v}
    if isinstance(v, dict):
        if "__bracket__" in v:
            return _parse_bracket_inner(v["__bracket__"])
        t = v.get("__type__")
        if t == "utxt":
            return decode_utxt(v["__raw__"])
        if t == "true":
            return True
        if t == "fals":
            return False
        if t == "optr":
            return {"type": "object", "ptr": optr_to_ptr(v["__raw__"])}
        if t is not None:
            return {"type": "raw", "value": f"{t}({v.get('__raw__', '')})"}
        if _is_object_record(v):
            return {"type": "object", "ptr": _record_ptr(v)}
        if _is_constant_record(v):
            name = decode_value(v.get("seld"))
            if isinstance(name, dict) and name.get("type") == "text":
                return {
                    "type": "constant",
                    "name": name["value"],
                    "truncated": name["truncated"],
                }
        return {"type": "raw", "value": str(v)}
    return {"type": "raw", "value": str(v)}


def parse_result_value(text: str) -> Any:
    """Decode the value of an `AEGetParamDesc(...)(----) as **** = <value> err=...` line."""
    from aemonitor.aedebug import Parser

    p = Parser(text.strip())
    return decode_value(p.read_value_part())


# ----------------------------
# Calls
# ----------------------------


def _receiver(attr: Dict[str, Any]) -> Dict[str, Any]:
    subj = attr.get("subj")
    me = attr.get("me")
    if _is_constant_record(subj):
        name = decode_value(subj.get("seld"))
        if isinstance(name, dict) and name.get("type") == "text":
            return {
                "kind": "class",
                "name": name["value"],
                "truncated": name["truncated"],
            }
    if _is_object_record(subj):
        return {"kind": "instance", "ptr": _record_ptr(subj)}
    if subj in (None, "NULL-impl") and _is_object_record(me):
        # `my someHandler_(...)`: sent to the script object itself
        return {"kind": "script", "ptr": _record_ptr(me)}
    return {"kind": "function"}


def decode_bridge_call(parsed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Decode a parsed `{ascr,psbr ...}` event into a bridge call, or None."""
    if (parsed.get("event_class"), parsed.get("event_id")) != BRIDGE_EVENT:
        return None
    params = parsed.get("params") or {}
    attr = parsed.get("attr") or {}
    if not isinstance(params, dict) or not isinstance(attr, dict):
        return None
    sel = decode_value(params.get("snam"))
    if not (isinstance(sel, dict) and sel.get("type") == "text"):
        return None
    args = decode_value(params.get("----", []))
    if not isinstance(args, list):
        args = [args]
    receiver = _receiver(attr)
    return {
        "return_id": parsed.get("return_id"),
        "selector": sel["value"],
        "selector_truncated": sel["truncated"],
        "receiver_kind": receiver["kind"],
        "receiver": receiver.get("name") or receiver.get("ptr"),
        "receiver_truncated": receiver.get("truncated", False),
        "args": args,
        "truncated": sel["truncated"]
        or receiver.get("truncated", False)
        or any(_value_truncated(a) for a in args),
    }


def decode_bridge_payload(payload: str) -> Optional[Dict[str, Any]]:
    return decode_bridge_call(parse_apple_event_debug(payload))


def _value_truncated(v: Any) -> bool:
    if isinstance(v, list):
        return any(_value_truncated(x) for x in v)
    return isinstance(v, dict) and bool(v.get("truncated"))


# ----------------------------
# Rendering
# ----------------------------

ELLIPSIS = "…"


def default_namer(ptr: str) -> str:
    return f"«object {ptr}»"


def _quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_value(v: Any, namer: Namer = default_namer) -> str:
    if v is None:
        return "missing value"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, list):
        return "{" + ", ".join(render_value(x, namer) for x in v) + "}"
    t = v.get("type")
    if t == "text":
        return _quote(v["value"] + (ELLIPSIS if v.get("truncated") else ""))
    if t == "object":
        return namer(v["ptr"]) if v.get("ptr") else "«object»"
    if t == "constant":
        return v["name"] + (ELLIPSIS if v.get("truncated") else "")
    if t == "missing":
        return "missing value"
    if t == "reference":
        return "(reference)"
    return str(v.get("value"))


def _receiver_source(call: Dict[str, Any], namer: Namer) -> Optional[str]:
    kind = call["receiver_kind"]
    if kind == "class":
        return call["receiver"] + (ELLIPSIS if call.get("receiver_truncated") else "")
    if kind == "instance":
        return namer(call["receiver"]) if call.get("receiver") else "«object»"
    if kind == "script":
        return "my"
    return None


def render_message(call: Dict[str, Any], namer: Namer = default_namer) -> str:
    """The selector and arguments: `alloc()`, `setMessageText:"Hello"`, `nodeWith…(...)`."""
    sel = call["selector"]
    args = call["args"]
    rendered = [render_value(a, namer) for a in args]
    if call.get("selector_truncated"):
        # Never guess the missing part of a truncated selector
        return f"{sel}{ELLIPSIS}({', '.join(rendered)})"
    parts = sel.split("_")
    if sel.endswith("_") and len(parts) - 1 == len(args) and all(parts[:-1]):
        # setMessageText_ + ["Hello"] -> setMessageText:"Hello"
        return " ".join(f"{p}:{a}" for p, a in zip(parts[:-1], rendered))
    return f"{sel}({', '.join(rendered)})"


def render_call(call: Dict[str, Any], namer: Namer = default_namer) -> str:
    receiver = _receiver_source(call, namer)
    message = render_message(call, namer)
    if receiver is None:
        return message
    if receiver == "my":
        return f"my {message}"
    return f"{receiver}'s {message}"
