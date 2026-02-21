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
