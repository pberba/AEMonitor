import re
import os

from typing import Any, Dict, List, Optional

from aemonitor.aedebug import parse_apple_event_debug, decode_utxt_raw, find_matching
from aemonitor.ast import derive_ast

NULL_IMPL = "0xNULL-impl"

# First bytes of an OSA compiled-script blob identify the scripting language it
# was compiled with. The unified log truncates these blobs to ~32 bytes, so the
# script body is never recoverable; only the language, container type and
# declared length can be surfaced.
_OSA_MAGICS = {
    "4a734f7361444153": "JavaScript",  # "JsOsaDAS" (JXA)
    "4661736455415320": "AppleScript",  # "FasdUAS "
}

# A printf-style conversion specifier in a unified-log formatString, capturing an
# optional {...} annotation (e.g. {private}, {public}) and the conversion char.
_SPEC_RE = re.compile(
    r"%(\{[^}]*\})?[#0\- +']*[*0-9.]*(?:hh|ll|[hlLqjzt])?([@diouxXeEfgGaAcsSpn%])"
)


def _extract_value(text: str, i: int) -> str:
    """Extract value at position i: either a balanced {..} block or best effort string parsing."""
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        return ""
    if text[i] == "{":
        depth, start = 0, i
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
            i += 1
        return text[start:]
    start = i
    while i < len(text) and text[i] not in " \t\r\n,":
        i += 1
    return text[start:i]


def _extract_src_raw(message: str) -> Optional[str]:
    """Return the balanced ``src=`` value from a cloneForCompatability message.

    The format is ``cloneForCompatability(src=<VALUE> dst=<ptr>)`` where VALUE may
    be a quoted string, a ``type(len/$hex)`` blob, a ``[...]`` list, a ``{...}``
    record, or a bare token. The value ends at the top-level `` dst=`` (the hex
    dump is frequently truncated, so the closing ``)`` is often absent).
    """
    i = message.find("(src=")
    if i == -1:
        return None
    i += len("(src=")
    start = i
    depth = 0
    in_quote = ""
    while i < len(message):
        ch = message[i]
        if in_quote:
            if ch == in_quote and message[i - 1] != "\\":
                in_quote = ""
        elif ch in "\"'":
            in_quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break  # closing ')' of cloneForCompatability(
            depth -= 1
        elif depth == 0 and message.startswith(" dst=", i):
            break
        i += 1
    return message[start:i].strip() or None


def _decode_strings(text: str) -> List[str]:
    """Decode every readable string (utxt or quoted) found in a src blob, in order."""
    out: List[str] = []
    for m in re.finditer(r'utxt\((\d+/\$[0-9a-fA-F.]*)\)|"((?:[^"\\]|\\.)*)"', text):
        if m.group(1) is not None:
            try:
                out.append(decode_utxt_raw(m.group(1)))
            except Exception:
                continue
        else:
            out.append(m.group(2))
    return out


def _describe_compiled_script(type_name: str, raw: str) -> Optional[str]:
    """Typed placeholder for a compiled-OSA-script clone whose body the log truncated.

    ``raw`` is ``<declared_len>/$<first ~32 bytes hex>...``. Returns None when the
    blob is not a recognizable OSA script (so opaque ``----``/``tdta`` data is left
    dropped rather than mislabelled).
    """
    length, _, hex_part = raw.partition("/$")
    head = hex_part.strip(".").lower()[:16]
    lang = next((name for sig, name in _OSA_MAGICS.items() if head.startswith(sig)), None)
    if lang is None:
        if type_name == "scpt":
            lang = "OSA"  # scpt is by definition a compiled script
        else:
            return None  # ---- / tdta without OSA magic: not a script we can label
    # '----' is the direct-object keyword, not a container type; only scpt/tdta name one.
    container = f" · {type_name}" if type_name in ("scpt", "tdta") else ""
    return (
        f"<compiled {lang} script{container} · {length.strip()} bytes · "
        "source redacted from unified log>"
    )


def _decompile_record(raw: str) -> Optional[str]:
    """Decompile a structured Apple-Event/object-specifier clone record to AppleScript."""
    try:
        parsed = parse_apple_event_debug(raw)
    except Exception:
        return None
    if parsed.get("event_class") is None:
        return None
    event_for_ast = {**parsed, "params": parsed.get("params") or {}}
    try:
        return derive_ast(event_for_ast)
    except Exception:
        return None


def extract_clone_src(message: str) -> Optional[str]:
    """Extract a human-readable source from a 'cloneForCompatability' log message.

    Handles:
      - ``src="..."``                  raw quoted ASCII shell commands.
      - ``src=utxt(...)``              a single utxt-encoded Unicode string.
      - ``src=[utxt(...)/"..."]``      a list of strings (joined).
      - ``src=scpt/tdta/----(...)``    compiled OSA scripts -> typed placeholder
                                       (body is truncated out of the log).
      - ``src={...}``                  object-specifier/event records -> AppleScript.

    Everything else (pointers, scalars, enums, type codes, opaque binary) is dropped.
    """
    if "cloneForCompatability" not in message:
        return None
    raw = _extract_src_raw(message)
    if not raw:
        return None

    if raw[0] == '"':
        return raw[1:-1] if raw.endswith('"') and len(raw) > 1 else raw[1:]

    single_utxt = re.fullmatch(r"utxt\((.*)\)", raw, re.S)
    if single_utxt:
        try:
            return decode_utxt_raw(single_utxt.group(1))
        except Exception:
            return None

    if raw[0] == "[":
        return " ".join(s for s in _decode_strings(raw) if s) or None

    compiled = re.fullmatch(r"(scpt|tdta|----)\((\d+/\$[0-9a-fA-F.]*)\)", raw, re.S)
    if compiled:
        return _describe_compiled_script(compiled.group(1), compiled.group(2))

    if raw[0] == "{":
        return _decompile_record(raw)

    return None


def is_private_only(format_string: str) -> bool:
    """True when a record's content comes entirely from ``%{private}`` fields.

    Such a record would be redacted to ``<private>`` on a stock macOS (where
    private-data logging is off), carrying no analyst value. Pointers (``%p``) and
    a leading ``%{public}s`` (the sender-image prefix, empty for these AE logs)
    are not treated as content.
    """
    if not format_string:
        return False
    saw_private = False
    saw_public_content = False
    for idx, m in enumerate(_SPEC_RE.finditer(format_string)):
        ann, conv = m.group(1) or "", m.group(2)
        if conv == "%":
            continue
        if "private" in ann or "sensitive" in ann:
            saw_private = True
        elif conv == "p":
            continue  # raw pointer, no content
        elif conv == "s" and "public" in ann and idx == 0:
            continue  # leading %{public}s sender-image prefix (empty in AE logs)
        else:
            saw_public_content = True
    return saw_private and not saw_public_content


def extract_apple_events(message: str) -> Dict[str, str]:
    """
    Extracts Apple Events event and reply payloads from a unified log message.

    Naively examines the log message for `event=` and `reply=` keys, and parses the associated
    values, which can be either a balanced brace-delimited string (e.g., {aevt,...})
    or a simple token. Handles special "0xNULL-impl" as an absent value for the reply.
    Keys with absent or NULL-like values are omitted from the result.

    Args:
        message (str): Log message string to parse.

    Returns:
        Dict[str, str]: Dictionary with keys `"event"` and/or `"reply"` only when present.
        Keys with absent or NULL-like values are omitted.

    Examples:
        >>> extract_apple_events("event={syso,...} reply={aevt,...}")
        {'event': '{syso,...}', 'reply': '{aevt,...}'}

        >>> extract_apple_events("event={} reply=0xNULL-impl")
        {'event': '{}'}

        >>> extract_apple_events("")
        {}
    """
    out: Dict[str, str] = {}
    for key in ("event", "reply"):
        m = re.search(f"{key}=", message)
        if not m:
            continue
        val = _extract_value(message, m.end())
        if val and val != NULL_IMPL:
            out[key] = val
    return out


def enrich_unified_log(unified_log: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich a unified log entry with extracted Apple Events and decompiled AppleScript."""

    raw_message = unified_log["eventMessage"]
    unified_log["appleEvent"] = {}
    # On stock macOS this record would be redacted to <private>; used by the UI's
    # "stock macOS visibility" toggle. Clones are always src=%{private}s.
    unified_log["private_only"] = is_private_only(unified_log.get("formatString", ""))

    if "cloneForCompatability" in raw_message:
        unified_log["appleEvent"]["clone"] = extract_clone_src(raw_message)
        return unified_log

    if "event=" not in raw_message and "reply=" not in raw_message:
        return None

    # Extract Apple Events event and reply payloads from the raw message if present
    raw_apple_event = extract_apple_events(raw_message)
    for key, payload in raw_apple_event.items():
        parsed = parse_apple_event_debug(payload)
        # Probably not an apple event
        if parsed.get("event_class") is None:
            return None

        # The target is kept accurate on the enriched event, but "tell application X"
        # is dropped from the rendered AppleScript when it would be redundant (the
        # target is the process itself).
        process_image_path = unified_log.get("processImagePath", "")
        curr_process = os.path.basename(process_image_path)
        omit_target = False
        if key == "event" and "reply" in raw_apple_event:
            # Receiver side (event+reply logged together): the process handled an
            # event addressed to itself, so the target is this process.
            parsed["target"] = curr_process
            omit_target = True
        elif key == "event" and "target" in parsed:
            if curr_process == parsed["target"]:
                omit_target = True
        elif "Self" in raw_message:
            # Sent to self: the target is this process.
            parsed["target"] = curr_process
            omit_target = True

        # derive_ast expects params to be a dict; handle None from parse. The real
        # target is kept so the decompiler can resolve the app's terminology
        # (SDEFS[target]); derive_ast then drops the redundant "tell application X".
        event_for_ast = {**parsed, "params": parsed.get("params") or {}}
        applescript = derive_ast(event_for_ast, omit_target=omit_target)
        unified_log["appleEvent"][key] = {
            "raw": payload,
            "return_id": parsed.get("return_id"),
            "event_class": parsed.get("event_class"),
            "event_id": parsed.get("event_id"),
            "target": parsed.get("target"),
            "applescript": applescript,
        }

    return unified_log
