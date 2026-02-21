"""
CLI for aemonitor: stream and parse Apple Events from macOS unified logs.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, Iterator, Optional

# ANSI color codes (empty when colors disabled)
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_MAGENTA = "\033[35m"
_WHITE = "\033[37m"

# Field widths for space-padded output
_PID_WIDTH = 6
_THREAD_ACTIVITY_WIDTH = 18  # [0x1234][0x12345678]
_RETURN_ID_WIDTH = 8
_PROCESS_WIDTH = 12

from aemonitor.unified_logs import enrich_unified_log

# Base predicate for Apple Events subsystem logs with event=, reply=+returnID=, or cloneForCompatability
BASE_PREDICATE = (
    '((subsystem == "com.apple.appleevents") AND '
    '(eventMessage contains[c] "event={" OR '
    '(eventMessage contains[c] "reply={" AND eventMessage contains[c] "returnID=") OR '
    '(eventMessage contains[c] "cloneForCompatability(" AND (eventMessage contains[c] "src=\\""))))'
)


def _build_predicate(extra: Optional[str]) -> str:
    """Combine base predicate with optional extra filter."""
    if extra:
        return f"({BASE_PREDICATE}) AND ({extra})"
    return BASE_PREDICATE


def _run_log_stream(predicate: str) -> subprocess.Popen:
    """Run log stream with predicate and ndjson output.
    Uses --level debug so Apple Events (often logged at info level) are included.
    """
    cmd = [
        "/usr/bin/log",
        "stream",
        "--predicate",
        predicate,
        "--style",
        "ndjson",
        "--level",
        "debug",
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=None,  # inherit stderr so log errors go to terminal
        text=True,
        bufsize=1,
    )


def _run_log_show(archive_path: str, predicate: str) -> subprocess.Popen:
    """Run log show on archive with predicate and ndjson output."""
    cmd = [
        "/usr/bin/log",
        "show",
        "--archive",
        archive_path,
        "--predicate",
        predicate,
        "--style",
        "ndjson",
        "--debug",
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=None,  # inherit stderr so log errors go to terminal
        text=True,
        bufsize=1,
    )


def _iter_ndjson_lines(proc: subprocess.Popen) -> Iterator[Dict[str, Any]]:
    """Yield parsed JSON dicts from process stdout, one per line."""
    assert proc.stdout is not None
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.strip()
        if not line or "Filtering the log data using" in line:
            continue
        try:
            entry = json.loads(line)
            if isinstance(entry, dict) and "finished" in entry:
                continue
            yield entry
        except json.JSONDecodeError:
            continue


def _iter_ndjson_from_file(path: str) -> Iterator[Dict[str, Any]]:
    """Yield parsed JSON dicts from an NDJSON file, one line at a time."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if isinstance(entry, dict) and "finished" in entry:
                    continue
                yield entry
            except json.JSONDecodeError:
                continue


def _colorize(text: str, *codes: str, use_color: bool = True) -> str:
    """Wrap text with ANSI color codes. Returns plain text if use_color is False."""
    if not use_color:
        return text
    return "".join(codes) + text + _RESET


def _format_decompiled_message(
    enriched: Dict[str, Any], *, use_color: bool = True
) -> str:
    """Build the message part for syslog format: decompiled AppleScript instead of eventMessage."""
    ae = enriched.get("appleEvent", {})
    # When both event and reply exist, only print reply
    if "event" in ae and "reply" in ae:
        label = _colorize("reply:", _BOLD, _YELLOW, use_color=use_color)
        return f"{label} {ae['reply'].get('applescript', '')}"
    if "event" in ae and ae["event"].get("applescript"):
        label = _colorize("event:", _BOLD, _YELLOW, use_color=use_color)
        return f"{label} {ae['event']['applescript']}"
    if "reply" in ae and ae["reply"].get("applescript"):
        label = _colorize("reply:", _BOLD, _YELLOW, use_color=use_color)
        return f"{label} {ae['reply']['applescript']}"
    # Fallback to raw eventMessage if no applescript (e.g. parse failed)
    return enriched.get("eventMessage", "")


def _process_and_category_from_image_path(path: str) -> tuple[str, str]:
    """Derive process name and category from processImagePath."""
    if not path:
        return "unknown", ""
    process = os.path.basename(path)
    # For .app bundles (e.g. /Applications/Safari.app/Contents/MacOS/Safari), category = app name
    if ".app/" in path:
        app_path = path.split(".app/", 1)[0]
        category = os.path.basename(app_path)
        if category.endswith(".app"):
            category = category[:-4]
    else:
        category = ""
    return process, category


# Timestamp width for column alignment (e.g. 2026-02-12 23:18:43.444118+0000 = 31 chars)
_TS_WIDTH = 31


def _format_syslog_header(*, use_color: bool = True) -> str:
    """Return a header line for syslog output matching column layout."""
    ts = "TIMESTAMP".ljust(_TS_WIDTH)
    pid = "PID".rjust(_PID_WIDTH)
    thread_activity = "[thread][activity]".ljust(_THREAD_ACTIVITY_WIDTH)
    process = "[process]".ljust(_PROCESS_WIDTH + 2)  # +2 for brackets
    return_id = "[return]".ljust(_RETURN_ID_WIDTH + 2)
    msg = "EVENT"
    return (
        f"{_colorize(ts, _DIM, use_color=use_color)} "
        f"{_colorize(pid, _CYAN, use_color=use_color)} "
        f"{_colorize(thread_activity, _DIM, use_color=use_color)} "
        f"{_colorize(process, _GREEN, use_color=use_color)} "
        f"{_colorize(return_id, _MAGENTA, use_color=use_color)} "
        f"{_colorize(msg, _WHITE, use_color=use_color)}"
    )


def _to_hex(val: Any) -> str:
    """Convert thread/activity ID to hex string like log stream output."""
    if val is None:
        return "0x0"
    if isinstance(val, int):
        return hex(val)
    if isinstance(val, str):
        if val.startswith("0x"):
            return val
        try:
            return hex(int(val, 10))
        except (ValueError, TypeError):
            return val or "0x0"
    return "0x0"


def _format_thread_activity(entry: Dict[str, Any]) -> str:
    """Format threadID and activityIdentifier like macOS log stream --style syslog."""
    thread = _to_hex(entry.get("threadID") or entry.get("threadIdentifier"))
    activity = _to_hex(entry.get("activityIdentifier"))
    return f"[{thread}][{activity}]".ljust(_THREAD_ACTIVITY_WIDTH)


def _format_syslog_line(enriched: Dict[str, Any], *, use_color: bool = True) -> str:
    """Format enriched log entry similar to log show syslog style, with applescript from event/reply."""
    timestamp = (enriched.get("timestamp") or enriched.get("eventDate", ""))[
        :_TS_WIDTH
    ].ljust(_TS_WIDTH)
    pid = enriched.get("processID") or enriched.get("processIdentifier", 0)
    image_path = enriched.get("processImagePath", "")
    process, category = _process_and_category_from_image_path(image_path)
    return_id = enriched.get("appleEvent", {}).get("event", {}).get(
        "return_id", ""
    ) or enriched.get("appleEvent", {}).get("reply", {}).get("return_id", "")

    pid_str = str(pid).rjust(_PID_WIDTH)
    thread_activity_str = _format_thread_activity(enriched)
    return_id_str = str(return_id).rjust(_RETURN_ID_WIDTH)
    process_str = (
        process[:_PROCESS_WIDTH] if len(process) > _PROCESS_WIDTH else process
    ).ljust(_PROCESS_WIDTH)

    message = _format_decompiled_message(enriched, use_color=use_color)

    ts_part = _colorize(timestamp, _DIM, use_color=use_color)
    pid_part = _colorize(pid_str, _CYAN, use_color=use_color)
    thread_activity_part = _colorize(thread_activity_str, _DIM, use_color=use_color)
    process_part = _colorize(f"[{process_str}]", _GREEN, use_color=use_color)
    return_part = _colorize(f"[{return_id_str}]", _MAGENTA, use_color=use_color)
    msg_part = _colorize(message, _WHITE, use_color=use_color)

    return f"{ts_part} {pid_part} {thread_activity_part} {process_part} {return_part} {msg_part}"


def _ensure_process_image_path(entry: Dict[str, Any]) -> None:
    """Ensure processImagePath exists for enrich_unified_log (uses it for reply target)."""
    entry.setdefault("processImagePath", "")


def _escape_clone_str(s: str) -> str:
    """Escape clone string for safe output (handles quotes, backslashes, control chars)."""
    return json.dumps(s, ensure_ascii=False)


def _format_clone_syslog_line(
    entry: Dict[str, Any], clone_str: str, *, use_color: bool = True
) -> str:
    """Format a cloneForCompatability log entry as syslog with message 'clone: <s>'."""
    timestamp = (entry.get("timestamp") or entry.get("eventDate", ""))[
        :_TS_WIDTH
    ].ljust(_TS_WIDTH)
    pid = entry.get("processID") or entry.get("processIdentifier", 0)
    image_path = entry.get("processImagePath", "")
    process, _ = _process_and_category_from_image_path(image_path)

    pid_str = str(pid).rjust(_PID_WIDTH)
    thread_activity_str = _format_thread_activity(entry)
    process_str = (
        process[:_PROCESS_WIDTH] if len(process) > _PROCESS_WIDTH else process
    ).ljust(_PROCESS_WIDTH)

    return_id_placeholder = _colorize(
        f"[{'':<{_RETURN_ID_WIDTH}}]", _MAGENTA, use_color=use_color
    )
    clone_label = _colorize("clone:", _BOLD, _YELLOW, use_color=use_color)
    clone_content = _colorize(
        f" {_escape_clone_str(clone_str)}", _DIM, use_color=use_color
    )

    ts_part = _colorize(timestamp, _DIM, use_color=use_color)
    pid_part = _colorize(pid_str, _CYAN, use_color=use_color)
    thread_activity_part = _colorize(thread_activity_str, _DIM, use_color=use_color)
    process_part = _colorize(f"[{process_str}]", _GREEN, use_color=use_color)

    return f"{ts_part} {pid_part} {thread_activity_part} {process_part} {return_id_placeholder} {clone_label}{clone_content}"


def _process_and_output(
    entry: Dict[str, Any],
    output_format: str,
    *,
    skip_empty: bool = True,
    use_color: bool = True,
) -> Optional[str]:
    """
    Enrich a log entry and return formatted output, or None if skipped.
    """
    if "eventMessage" not in entry:
        return None
    if (
        not (("event=" in entry["eventMessage"] or "reply=" in entry["eventMessage"]))
        and not "cloneForCompatability" in entry["eventMessage"]
    ):
        return None
    _ensure_process_image_path(entry)

    try:
        enriched = enrich_unified_log(entry)
        if enriched is None:
            return None
    except Exception:
        return None
    if output_format == "ndjson":
        # Omit clone, event, reply when None or undefined
        filtered = dict(enriched)
        if "appleEvent" in filtered:
            ae = dict(filtered["appleEvent"])
            for key in ("clone", "event", "reply"):
                if ae.get(key) is None:
                    ae.pop(key, None)
            filtered["appleEvent"] = ae
            if not ae:
                return None
        return json.dumps(filtered)

    if "clone" in enriched["appleEvent"]:
        # Track the last printed clone value using a function attribute
        # to avoid printing the same clone value multiple times
        # This is a hack to avoid printing the same clone value multiple times
        clone_val = enriched["appleEvent"]["clone"]
        if (
            not hasattr(_process_and_output, "_last_clone")
            or _process_and_output._last_clone is None
        ):
            _process_and_output._last_clone = None

        if (
            clone_val is None
            or len(clone_val) <= 16
            or clone_val == _process_and_output._last_clone
        ):
            return None

        _process_and_output._last_clone = clone_val
        return _format_clone_syslog_line(
            enriched, enriched["appleEvent"]["clone"], use_color=use_color
        )
    return _format_syslog_line(enriched, use_color=use_color)


def _stream_or_parse(
    *,
    archive_path: Optional[str] = None,
    predicate_extra: Optional[str] = None,
    output_format: str,
    use_color: bool = True,
) -> int:
    proc: Optional[subprocess.Popen] = None
    if archive_path and archive_path.endswith(".ndjson"):
        # Read line-by-line from NDJSON file (no log command needed)
        entries = _iter_ndjson_from_file(archive_path)
    else:
        predicate = _build_predicate(predicate_extra)
        if archive_path:
            proc = _run_log_show(archive_path, predicate)
            entries = _iter_ndjson_lines(proc)
        else:
            proc = _run_log_stream(predicate)
            print(
                "Streaming Apple Events... (run AppleScripts to see output, Ctrl+C to stop)",
                file=sys.stderr,
            )
            entries = _iter_ndjson_lines(proc)

    exit_code: Optional[int] = None  # None = normal completion
    try:
        if output_format == "syslog":
            print(_format_syslog_header(use_color=use_color), flush=True)

        for entry in entries:
            out = _process_and_output(entry, output_format, use_color=use_color)
            if out is not None:
                print(out, flush=True)
    except BrokenPipeError:
        # Consumer closed pipe (e.g. head, less) - exit gracefully
        exit_code = 0
    except KeyboardInterrupt:
        exit_code = 130  # 128 + SIGINT(2)
    finally:
        if proc is not None:
            if exit_code is not None:
                proc.terminate()
            proc.wait()

    return exit_code if exit_code is not None else (proc.returncode or 0) if proc else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="aemonitor",
        description="Stream or parse Apple Events from macOS unified logs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # stream
    stream_parser = subparsers.add_parser(
        "stream",
        help="Stream Apple Events logs in real time (run AppleScripts in another terminal to see output)",
    )
    stream_parser.add_argument(
        "--style",
        choices=["syslog", "ndjson"],
        default="syslog",
        help="Output style: syslog (human-readable with decompiled AppleScript) or ndjson (raw enriched JSON)",
    )
    stream_parser.add_argument(
        "--predicate",
        metavar="PREDICATE",
        default=None,
        help="Optional extra NSPredicate to AND with the base Apple Events filter",
    )
    stream_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful when piping to files)",
    )

    # parse
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse Apple Events from a .logarchive or .ndjson file",
    )
    parse_parser.add_argument(
        "input",
        metavar="PATH",
        help="Path to a .logarchive (uses log show) or .ndjson file (read line-by-line)",
    )
    parse_parser.add_argument(
        "--style",
        choices=["syslog", "ndjson"],
        default="syslog",
        help="Output style: syslog (human-readable with decompiled AppleScript) or ndjson (raw enriched JSON)",
    )
    parse_parser.add_argument(
        "--predicate",
        metavar="PREDICATE",
        default=None,
        help="Optional extra NSPredicate to AND with the base Apple Events filter",
    )
    parse_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful when piping to files)",
    )

    args = parser.parse_args()
    use_color = sys.stdout.isatty() and not getattr(args, "no_color", False)

    try:
        if args.command == "stream":
            return _stream_or_parse(
                archive_path=None,
                predicate_extra=args.predicate,
                output_format=args.style,
                use_color=use_color,
            )
        if args.command == "parse":
            input_path = args.input
            # Only need log command for .logarchive; .ndjson is read directly
            if not input_path.endswith(".ndjson") and (
                not os.path.isfile("/usr/bin/log")
                or not os.access("/usr/bin/log", os.X_OK)
            ):
                print("aemonitor: /usr/bin/log not found (macOS only)", file=sys.stderr)
                return 1
            return _stream_or_parse(
                archive_path=input_path,
                predicate_extra=args.predicate,
                output_format=args.style,
                use_color=use_color,
            )
    except KeyboardInterrupt:
        return 130
    return 1
