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
| `--no-objc` | Don't show AppleScriptObjC bridge calls |
| `--objc-results` | Show bridge-call return values (`stream` reads many more log lines) |
| `--indicators` | Print bridge-call indicators as they fire, and a summary at the end |

## AppleScriptObjC bridge calls

> [!IMPORTANT]
> This needs [private data enabled](https://www.jamf.com/blog/unified-logs-how-to-enable-private-data/) for `com.apple.appleevents`. Without it, these lines are redacted by macOS and nothing below is visible.

AppleScriptObjC (`use framework "Foundation"`) sends every Objective-C message, and every bridged C function call, through an internal `ascr,psbr` Apple event. The AE framework logs it once per call, at debug level:

```
cloneForCompatability(src={ascr,psbr target='psn '[Script Editor] {snam=utxt(22/$73007400720069006e006700560061006c0075006500),----=[]} attr:{subj={form=ID  ,want=ocid,seld=optr(8/$801f730e0b000000),from=NULL-impl},...} returnID=4313} dst=0x16af455a4
```

`aemonitor` decodes these into pseudo-AppleScript, one line per call. Objects are named after the call that created them (`NSAlert's alloc()` gives `alert1`), or `obj1`, `obj2`, ... when that call wasn't seen. With `--objc-results`, return values are paired with their calls. This is part of a telemetry test script that asks for a password and checks it with OpenDirectory (`--objc-results --indicators`, columns trimmed):

```
[    4313] objc: secureTextFiel1's stringValue()
[        ] indicator: objc.cred.prompt_with_input Alert with a text field accessory shown, then its value read [returnIDs: -14976, -29223, 28301, 4313]
[    4313] objc: --> stringValue1
[   10552] objc: ODSession's defaultSession()
[        ] indicator: objc.cred.od_verify Password checked through OpenDirectory [returnIDs: 10552]
[   10552] objc: --> session1
[   -2074] objc: ODNode's nodeWithSession_…(session1, "/Local/Default", (reference))
[   -2074] objc: --> {node1, missing value}
[   -9644] objc: NSUserName()
[   -9644] objc: --> userName1
[   -2094] objc: node1's recordWithRecord…("dsRecTypeStandar…", userName1, missing value, (reference))
[   -2094] objc: --> {record1, missing value}
[  -13458] objc: record1's verifyPassword_e…(stringValue1, (reference))
[  -13458] objc: --> {false, error1}
[        ] indicator: objc.cred.verify_result Result of an OpenDirectory password check (false) [returnIDs: -13458]
[   -4696] objc: secureTextFiel1's setStringValue:""
```

Limits to keep in mind:

- **16 characters.** Strings, selectors and class names are logged as their first 32 bytes of UTF-16, so anything longer is cut (`verifyPassword_e…`, `NSSecureTextFiel…`). A truncated selector is shown as `selector…(args)`; the missing part is never guessed.
- **Return values** are read from the log by order, not by ID: the result is the first `(----) as **** =` read after an `errn` anchor on the same thread. It was checked on macOS 26.2 only. If no anchor shows up, the call is printed without a result.
- **Secrets are logged as is.** If a script coerces a password field's value to text (`stringValue() as text`), the typed password is in the log (its first 16 characters). It also shows up in `dscl . -authonly` commands. `aemonitor` prints these unchanged, so treat its output with the same care as the logs it came from.
- **JXA is not covered.** JXA's Objective-C bridge does not use Apple events, and a JXA run of the same behaviour logged no bridge calls.
- Observed with Script Editor, a compiled applet and `osascript` on macOS 26.2. Calls on a class that doesn't exist also show up as a real `event={ascr,psbr ...}`. They are reported once, as `--> error: lookup failed`. Unlike the clones, that line is logged as public, so a stock Mac (private data off) still shows the class and selector.

### Indicators

`--indicators` names what it sees, per process, with the returnIDs of the supporting calls. Each one is a lead, not a verdict: `NSAlert` and `NSURLSession` have plenty of legitimate uses in admin scripts. Everything matches on prefixes because of the 16-character limit.

| Indicator | Fires on |
|---|---|
| `objc.ui.alert` | `NSAlert` then `runModal` |
| `objc.ui.headless_to_gui` | `setActivationPol…` then `activateIgnoring…` |
| `objc.cred.secure_field` | a `NSSecureTextFiel…` class call |
| `objc.cred.prompt_with_input` | a text field created, `setAccessoryView…`, `runModal`, then `stringValue` |
| `objc.cred.window_raised` | `setLevel:` with `NSStatusWindowLe…`, `NSScreenSaverWin…`, `NSPopUpMenuWindo…` or `NSModalPanelWind…` |
| `objc.cred.od_verify` | `ODSession` / `ODNode` class calls, or `verifyPassword_e…` |
| `objc.cred.verify_result` | the result of `verifyPassword_e…` (needs results) |
| `objc.cred.reprompt_loop` | a second prompt after a password check (`verifyPassword_e…` or `dscl . -authonly`) that didn't return true |
| `objc.cred.cleartext_leak` | a `stringValue` read after a dialog that is logged as text (needs results) |
| `objc.cred.saved_to_disk` | `writeToFile_atom…` on text read from a dialog |
| `objc.lure.app_icon` | `setIcon:` on an alert, with the icon loaded by `pathForResource:` / `initByReferencin…` / `initWithContents…` |
| `objc.net.url` | `NSURL's URLWithString:` |
| `objc.net.session` | `NSURLSession`, `NSURLSessionConf…`, `NSMutableURLRequ…`, `dataTaskWithRequ…`, `dataTaskWithURL:`, `dataWithContents…` |
| `objc.net.post` | `setHTTPMethod:"POST"` or `setHTTPBody:` |
| `objc.file.stage` | `createDirectoryA…`, `createFileAtPath…`, `writeToFile_atom…`, `setAttributes_of…` |
| `objc.exec.task` | `NSTask`, `launchedTaskWith…`, `launchAndReturnE…`, `NSWorkspace` + `openURL:` / `launchApplicati…` |
| `objc.recon.region` | `NSLocale`, `NSTimeZone's systemTimeZone` and the `com.apple.HITool…` / `AppleEnabledInpu…` keyboard settings, all in one process |
| `objc.bridge.failed_lookup` | a bridge call to a class that doesn't exist |

To detect without `aemonitor`, search the raw `eventMessage` for the UTF-16LE hex of these prefixes. `aemonitor needles` prints all of them, for example:

```
objc.cred.od_verify	verifyPassword_e	760065007200690066007900500061007300730077006f00720064005f006500
objc.cred.secure_field	NSSecureTextFiel	4e00530053006500630075007200650054006500780074004600690065006c00
objc.net.session	NSURLSession	4e005300550052004c00530065007300730069006f006e00
```

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
