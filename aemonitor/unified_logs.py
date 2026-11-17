import re
import os

from typing import Any, Dict, Optional

from aemonitor.aedebug import parse_apple_event_debug, decode_utxt_raw
from aemonitor.ast import derive_ast

NULL_IMPL = "0xNULL-impl"


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


def extract_clone_src(message: str) -> Optional[str]:
    """
    Naively extracts the source command from a 'cloneForCompatability' unified log message.
    Most of the surrounding data in these messages is redundant; only ASCII strings
    longer than 16 bytes are considered for extraction.

    Only supports:
      - src=utxt(...)  Extracts and decodes Apple event utxt-encoded bytes.
      - src="..."     Extracts raw quoted ASCII shell commands.
    """
    if "cloneForCompatability" not in message:
        return None
    if "src=utxt" in message:
        _raw = message.split("src=utxt(", 1)[1].split(") dst=", 1)[0]
        return decode_utxt_raw(_raw)
    elif 'src="' in message:
        _raw = message.split('src="', 1)[1].split('" dst=', 1)[0]
        return _raw
    return None


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
