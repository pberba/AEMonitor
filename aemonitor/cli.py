"""
CLI for aemonitor: stream and parse Apple Events from macOS unified logs.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, Iterator, List, Optional

# ANSI color codes (empty when colors disabled)
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_MAGENTA = "\033[35m"
_WHITE = "\033[37m"
_RED = "\033[31m"

# Field widths for space-padded output
_PID_WIDTH = 6
_THREAD_ACTIVITY_WIDTH = 18  # [0x1234][0x12345678]
_RETURN_ID_WIDTH = 8
_PROCESS_WIDTH = 12

from aemonitor.native_stream import (
    NativeDependenciesMissing,
    NativeStreamUnavailable,
    iter_live_entries,
)
from aemonitor.indicators import Finding, IndicatorEngine, hex_needles, summarize
from aemonitor.objc_correlate import BridgeTracker, is_anchor, is_create, is_result
from aemonitor.unified_logs import enrich_unified_log

# cloneForCompatability src encodings extract_clone_src can turn into text: quoted
# strings, utxt, lists of strings, records, and compiled scripts (as a placeholder)
CLONE_SRC_PREFIXES = ('"', "utxt(", "[", "{", "scpt(", "tdta(", "----(")
# Apple events: event=, reply=+returnID=, and cloneForCompatability sources
_AE_CLAUSES = (
    'eventMessage contains[c] "event={" OR '
    '(eventMessage contains[c] "reply={" AND eventMessage contains[c] "returnID=") OR '
    + " OR ".join(
        "eventMessage contains " + json.dumps(f"cloneForCompatability(src={p}")
        for p in CLONE_SRC_PREFIXES
    )
)
# AppleScriptObjC bridge calls: one cloneForCompatability(src={ascr,psbr ...}) per call
_OBJC_CLAUSE = 'eventMessage contains "cloneForCompatability(src={ascr,psbr"'
# Bridge call return values: the errn anchor and the (----) read that follows it.
# Far noisier than the calls, so only added on request.
_OBJC_RESULT_CLAUSES = (
    'eventMessage contains "for keyword errn type long" OR '
    'eventMessage contains "(----) as **** =" OR '
    'eventMessage contains "AECreateAppleEvent("'
)


def _base_predicate(*, objc: bool = True, objc_results: bool = False) -> str:
    clauses = [_AE_CLAUSES]
    if objc:
        clauses.append(_OBJC_CLAUSE)
        if objc_results:
            clauses.append(_OBJC_RESULT_CLAUSES)
    return f'((subsystem == "com.apple.appleevents") AND ({" OR ".join(clauses)}))'


BASE_PREDICATE = _base_predicate()


def _build_predicate(
    extra: Optional[str], *, objc: bool = True, objc_results: bool = False
) -> str:
    """Combine base predicate with optional extra filter."""
    base = _base_predicate(objc=objc, objc_results=objc_results)
    if extra:
        return f"({base}) AND ({extra})"
    return base


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


NDJSON_SUFFIXES = (".ndjson", ".jsonl")


def is_ndjson_path(path: str) -> bool:
    """JSON-lines files are read directly; anything else goes to `log show`."""
    return path.lower().endswith(NDJSON_SUFFIXES)


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




def _row_prefix(entry: Dict[str, Any], return_id: Any, *, use_color: bool) -> str:
    """Timestamp, pid, thread/activity, process and return id columns."""
    timestamp = (entry.get("timestamp") or entry.get("eventDate", ""))[:_TS_WIDTH].ljust(
        _TS_WIDTH
    )
    pid = entry.get("processID") or entry.get("processIdentifier", 0)
    process, _ = _process_and_category_from_image_path(entry.get("processImagePath", ""))
    process_str = (
        process[:_PROCESS_WIDTH] if len(process) > _PROCESS_WIDTH else process
    ).ljust(_PROCESS_WIDTH)
    rid = "" if return_id is None else str(return_id)
    return (
        f"{_colorize(timestamp, _DIM, use_color=use_color)} "
        f"{_colorize(str(pid).rjust(_PID_WIDTH), _CYAN, use_color=use_color)} "
        f"{_colorize(_format_thread_activity(entry), _DIM, use_color=use_color)} "
        f"{_colorize(f'[{process_str}]', _GREEN, use_color=use_color)} "
        f"{_colorize(f'[{rid.rjust(_RETURN_ID_WIDTH)}]', _MAGENTA, use_color=use_color)}"
    )


def _format_objc_line(record: Dict[str, Any], *, use_color: bool = True) -> str:
    """A bridge call (`objc: alert1's runModal()`) or its result (`objc: --> 1000`)."""
    ae = record["appleEvent"]
    label = _colorize("objc:", _BOLD, _CYAN, use_color=use_color)
    if "objc" in ae:
        part = ae["objc"]
        message = _colorize(part.get("applescript", ""), _WHITE, use_color=use_color)
    else:
        part = ae["objc_result"]
        text = part.get("applescript", "")
        if not text.startswith(("as text", "then")):
            text = f"--> {text}"
        message = _colorize(text, _DIM, use_color=use_color)
    return f"{_row_prefix(record, part.get('return_id'), use_color=use_color)} {label} {message}"


def _format_finding_line(
    finding: Finding, record: Dict[str, Any], *, use_color: bool = True
) -> str:
    label = _colorize("indicator:", _BOLD, _RED, use_color=use_color)
    name = _colorize(finding.name, _BOLD, _RED, use_color=use_color)
    rids = ", ".join(str(r) for r in finding.return_ids)
    detail = f" ({finding.detail})" if finding.detail else ""
    rest = _colorize(f"{finding.description}{detail} [returnIDs: {rids}]", _WHITE, use_color=use_color)
    return f"{_row_prefix(record, None, use_color=use_color)} {label} {name} {rest}"


_SHORT_CLONE = 16


class OutputSession:
    """Turns raw unified log entries into output lines.

    Stateful: names bridge-call objects, pairs bridge calls with their results,
    tracks indicators per process and drops repeated clones. Use one per source, feed entries in log order and call `finish()` at
    the end.
    """

    def __init__(
        self,
        output_format: str,
        *,
        use_color: bool = True,
        objc: bool = True,
        objc_results: bool = False,
        indicators: bool = False,
    ) -> None:
        self.output_format = output_format
        self.use_color = use_color
        self.objc_results = objc_results
        self.tracker = BridgeTracker() if objc else None
        self.engine = IndicatorEngine() if indicators and objc else None
        self._last_clone: Optional[str] = None

    # --- entry points -------------------------------------------------------------

    def process(self, entry: Dict[str, Any]) -> List[str]:
        message = entry.get("eventMessage")
        if not message:
            return []
        if self.tracker is not None and (
            is_create(message) or is_anchor(message) or is_result(message)
        ):
            record = self.tracker.on_line(entry)
            if record is None:
                return []
            return self._emit(
                record, show=self.objc_results and not self._is_void(record)
            )

        if not (
            "event=" in message or "reply=" in message or "cloneForCompatability" in message
        ):
            return []
        _ensure_process_image_path(entry)
        try:
            enriched = enrich_unified_log(entry)
        except Exception:
            return []
        if enriched is None:
            return []
        ae = enriched["appleEvent"]
        if "objc" in ae:
            if self.tracker is None:
                return []
            record = self.tracker.on_call(enriched)
            if record is None:
                return []
            if "objc_result" in record["appleEvent"]:
                # A failed class lookup, reported against the call already shown
                return self._emit(record, show=self.objc_results)
            return self._emit(record)

        if "clone" in ae:
            clone = ae["clone"]
            if clone is None:
                return []
            if self.output_format == "ndjson":
                return self._emit(enriched)
            # Clones repeat and short ones are noise
            if len(clone) <= _SHORT_CLONE or clone == self._last_clone:
                return []
            self._last_clone = clone
        return self._emit(enriched)

    def finish(self) -> List[str]:
        out: List[str] = []
        if self.engine is not None and self.output_format == "syslog":
            findings = self.engine.findings()
            out.append("")
            out.append(_colorize(f"Indicators ({len(findings)}):", _BOLD, use_color=self.use_color))
            out += [f"  {line}" for line in summarize(findings)]
        return out

    # --- helpers ----------------------------------------------------------------------

    @staticmethod
    def _is_void(record: Dict[str, Any]) -> bool:
        return bool(record["appleEvent"].get("objc_result", {}).get("void"))

    def _emit(self, record: Dict[str, Any], *, show: bool = True) -> List[str]:
        """Format a record (if shown) and any indicators it fires."""
        out: List[str] = []
        if show:
            line = self._format(record)
            if line is not None:
                out.append(line)
        if self.engine is not None:
            for finding in self.engine.feed(record):
                if self.output_format == "ndjson":
                    out.append(json.dumps({**_finding_base(record), "finding": finding.to_dict()}))
                else:
                    out.append(_format_finding_line(finding, record, use_color=self.use_color))
        return out

    def _format(self, record: Dict[str, Any]) -> Optional[str]:
        ae = record.get("appleEvent", {})
        if self.output_format == "ndjson":
            # Omit clone, event, reply when None or undefined
            filtered = dict(record)
            ae = {k: v for k, v in ae.items() if v is not None}
            if not ae:
                return None
            filtered["appleEvent"] = ae
            return json.dumps(filtered)
        if "objc" in ae or "objc_result" in ae:
            return _format_objc_line(record, use_color=self.use_color)
        if "clone" in ae:
            return _format_clone_syslog_line(record, ae["clone"], use_color=self.use_color)
        return _format_syslog_line(record, use_color=self.use_color)


def _finding_base(record: Dict[str, Any]) -> Dict[str, Any]:
    keep = ("timestamp", "processID", "threadID", "processImagePath")
    return {k: record[k] for k in keep if k in record}


def _process_and_output(
    entry: Dict[str, Any],
    output_format: str,
    *,
    skip_empty: bool = True,
    use_color: bool = True,
    session: Optional[OutputSession] = None,
) -> Optional[str]:
    """
    Enrich a log entry and return formatted output, or None if skipped.

    Without a session the entry is handled on its own (no state carried over).
    """
    if session is None:
        session = OutputSession(output_format, use_color=use_color)
        lines = session.process(entry) + [
            line for line in session.finish() if line  # no indicator summary here
        ]
    else:
        lines = session.process(entry)
    return "\n".join(lines) if lines else None


def _stream_or_parse(
    *,
    archive_path: Optional[str] = None,
    predicate_extra: Optional[str] = None,
    output_format: str,
    use_color: bool = True,
    backend: str = "auto",
    objc: bool = True,
    objc_results: bool = False,
    indicators: bool = False,
) -> int:
    proc: Optional[subprocess.Popen] = None
    # Results are needed for indicators too, even when not shown;
    # for .ndjson and archives every line is read anyway
    predicate = _build_predicate(
        predicate_extra, objc=objc, objc_results=objc and (objc_results or indicators)
    )
    if archive_path and is_ndjson_path(archive_path):
        # Read line-by-line from NDJSON file (no log command needed)
        entries = _iter_ndjson_from_file(archive_path)
    elif archive_path:
        proc = _run_log_show(archive_path, predicate)
        entries = _iter_ndjson_lines(proc)
    else:
        entries = None
        if backend in ("auto", "native"):
            # In-process LoggingSupport stream: predicate never appears on a command line
            try:
                entries = iter_live_entries(predicate)
            except NativeStreamUnavailable as e:
                if backend == "native":
                    print(f"aemonitor: {e}", file=sys.stderr)
                    return 1
                # auto: fall back to `log stream`; only warn if the native extra is installed
                if not isinstance(e, NativeDependenciesMissing):
                    print(
                        f"aemonitor: native backend unavailable ({e}), falling back to log stream",
                        file=sys.stderr,
                    )
        if entries is None:
            proc = _run_log_stream(predicate)
            entries = _iter_ndjson_lines(proc)
        print(
            "Streaming Apple Events... (run AppleScripts to see output, Ctrl+C to stop)",
            file=sys.stderr,
        )

    session = OutputSession(
        output_format,
        use_color=use_color,
        objc=objc,
        objc_results=objc_results,
        indicators=indicators,
    )
    exit_code: Optional[int] = None  # None = normal completion
    try:
        if output_format == "syslog":
            print(_format_syslog_header(use_color=use_color), flush=True)

        for entry in entries:
            for out in session.process(entry):
                print(out, flush=True)
    except BrokenPipeError:
        # Consumer closed pipe (e.g. head, less) - exit gracefully
        exit_code = 0
    except KeyboardInterrupt:
        exit_code = 130  # 128 + SIGINT(2)
    finally:
        # Closing the generator stops a native stream
        entries.close()
        if proc is not None:
            if exit_code is not None:
                proc.terminate()
            proc.wait()
    if exit_code != 0:
        try:
            for out in session.finish():
                print(out, flush=True)
        except BrokenPipeError:
            pass

    return exit_code if exit_code is not None else (proc.returncode or 0) if proc else 0


def _add_common_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--style",
        choices=["syslog", "ndjson"],
        default="syslog",
        help="Output style: syslog (human-readable with decompiled AppleScript) or ndjson (raw enriched JSON)",
    )
    p.add_argument(
        "--predicate",
        metavar="PREDICATE",
        default=None,
        help="Optional extra NSPredicate to AND with the base Apple Events filter",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful when piping to files)",
    )
    objc = p.add_argument_group(
        "AppleScriptObjC bridge calls (need private data enabled for com.apple.appleevents)"
    )
    objc.add_argument(
        "--no-objc",
        action="store_true",
        help="Do not show AppleScriptObjC bridge calls",
    )
    objc.add_argument(
        "--objc-results",
        action="store_true",
        help="Show bridge call return values (streams many more log lines)",
    )
    objc.add_argument(
        "--indicators",
        action="store_true",
        help="Print suspicious-behaviour indicators as they fire, and a summary at the end",
    )


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
    _add_common_arguments(stream_parser)
    stream_parser.add_argument(
        "--backend",
        choices=["auto", "log", "native"],
        default="auto",
        help="auto (default): native if PyObjC is installed, otherwise log. "
        "log: run /usr/bin/log stream (predicate visible in ps). "
        "native: stream in-process via LoggingSupport (requires PyObjC)",
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
    _add_common_arguments(parse_parser)

    # needles
    subparsers.add_parser(
        "needles",
        help="Print the raw eventMessage hex strings behind the bridge-call indicators",
    )

    args = parser.parse_args()
    use_color = sys.stdout.isatty() and not getattr(args, "no_color", False)

    if args.command == "needles":
        for name, text, needle in hex_needles():
            print(f"{name}\t{text}\t{needle}")
        return 0

    options = dict(
        predicate_extra=args.predicate,
        output_format=args.style,
        use_color=use_color,
        objc=not args.no_objc,
        objc_results=args.objc_results,
        indicators=args.indicators,
    )
    try:
        if args.command == "stream":
            return _stream_or_parse(archive_path=None, backend=args.backend, **options)
        if args.command == "parse":
            input_path = args.input
            # Only need log command for .logarchive; .ndjson/.jsonl is read directly
            if not is_ndjson_path(input_path) and (
                not os.path.isfile("/usr/bin/log")
                or not os.access("/usr/bin/log", os.X_OK)
            ):
                print("aemonitor: /usr/bin/log not found (macOS only)", file=sys.stderr)
                return 1
            return _stream_or_parse(archive_path=input_path, **options)
    except KeyboardInterrupt:
        return 130
    return 1
