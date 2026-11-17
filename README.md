# AEMonitor

Apple Events Monitor — stream and parse Apple Events from macOS debug unified logs (`com.apple.appleevents` subsystem). This tool allows us to log activity by `osascript` that isn't captured by process creation telemetry.

![](https://pberba.github.io/assets/posts/20260221/00-macsync.png)

Read More: [AEMonitor: Monitoring Apple Events for Malware Analysis and Detection](https://pberba.github.io/security/2026/02/21/aemonitor/)


## Installation

### Using `uv` (recommended)

```bash
uv sync
uv run aemonitor stream
```

### Using `pip`

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
# aemonitor stream
```

### Running tests

To run the test suite with pytest:

```bash
uv sync --extra dev          
uv run pytest
```

## Usage

### Stream Apple Events in real time

```bash
aemonitor stream
```

Run AppleScripts in another terminal to see events as they occur. Press Ctrl+C to stop.

### Stream using the native macOS API

Following the [logStream example](https://github.com/objective-see/TAOMM/tree/main/Code/Vol%20II/CH%206/logStream) from Objective-See's TAOMM, you can opt to get the log stream directly from macOS. One benefit of this is that the filters aren't readable with `ps`, as they are when using `log stream --predicate ...`.

Install the `native` extra and `stream` uses it automatically:

```bash
uv sync --extra native
uv run aemonitor stream
```

If the native stream can't start, `stream` prints a warning and falls back to `/usr/bin/log`. Use `--backend native` to fail instead, or `--backend log` to always use `/usr/bin/log`.

### macOS app

A native window (AppKit via PyObjC) with a live event table, request/reply pairing, sidebar filters for indicators, processes, targets and event codes, muting (right-click), a detail pane, and Start/Stop. It can also open a `.logarchive` or `.ndjson` file (⌘O) and export the events shown (⌘S).

Build a self-contained `dist/AEMonitor.app` (Python, the AppleScript decompiler and PyObjC included):

```bash
uv run --group app pyinstaller --noconfirm aemonitor/app/AEMonitor.spec
```

Or run it from source with `uv run --extra native python -m aemonitor.app`. The app is ad-hoc signed and meant for the machine that built it; set `AEMONITOR_CODESIGN_IDENTITY` to sign with a Developer ID. Warnings go to `~/Library/Logs/AEMonitor.log`.

### Parse from a log archive or NDJSON file

```bash
aemonitor parse path/to/file.logarchive
aemonitor parse path/to/file.ndjson
```

### Options

| Option | Description |
|--------|-------------|
| `--style syslog` | Human-readable output with decompiled AppleScript (default) |
| `--style ndjson` | Raw enriched JSON output |
| `--predicate PREDICATE` | Extra NSPredicate to filter logs |
| `--backend auto\|native\|log` | (`stream` only) `auto` (default) streams in-process via LoggingSupport when the `native` extra is installed, otherwise uses `/usr/bin/log` |
| `--no-color` | Disable colored output (useful when piping) |

### Using as a module

To use this as a module, the main fields we need is `eventMessage` and `processImagePath`.

```python
from aemonitor import enrich_unified_log

enrich_unified_log({
    "eventMessage": "sendToSelf(), event={syso,exec ...",
    "processImagePath": "/usr/bin/osascript"
})
# this adds an `appleEvent` field
```

## Requirements

- macOS (uses `/usr/bin/log` for streaming and parsing `logarchive` file)
- Python 3.10+
- To fully observe all events, you must [enable private data in Unified Logs](https://www.jamf.com/blog/unified-logs-how-to-enable-private-data/)
