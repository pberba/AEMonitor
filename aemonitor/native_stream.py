"""
Stream unified logs in-process via the private LoggingSupport framework.

Unlike `/usr/bin/log stream --predicate ...`, the predicate is never placed on a
command line, so it isn't visible to other processes via `ps`. Requires PyObjC
(`pip install 'aemonitor[native]'`).

Based on the OSLogEventLiveStream approach from objective-see's TAOMM logStream sample.
"""

import queue
import sys
from datetime import datetime
from typing import Any, Dict, Iterator

LOGGING_SUPPORT = "/System/Library/PrivateFrameworks/LoggingSupport.framework"

# OSLogEventLiveStream flags: 0 = default, 1 = info, 2 = debug
_LEVEL_DEBUG = 2

# os_log_type_t -> `log --style ndjson` messageType
_MESSAGE_TYPES = {0: "Default", 1: "Info", 2: "Debug", 16: "Error", 17: "Fault"}

_STOP = object()


class NativeStreamUnavailable(RuntimeError):
    """Raised when PyObjC or LoggingSupport can't be loaded."""


class NativeDependenciesMissing(NativeStreamUnavailable):
    """Raised when PyObjC isn't installed (the `native` extra)."""


def _load_live_stream_class():
    try:
        import objc
        from Foundation import NSBundle
    except ImportError as e:
        raise NativeDependenciesMissing(
            "--backend native requires PyObjC: pip install 'aemonitor[native]'"
        ) from e

    bundle = NSBundle.bundleWithPath_(LOGGING_SUPPORT)
    if bundle is None or not bundle.load():
        raise NativeStreamUnavailable(f"could not load {LOGGING_SUPPORT}")
    try:
        live_stream = objc.lookUpClass("OSLogEventLiveStream")
    except objc.nosuchclass_error as e:
        raise NativeStreamUnavailable("OSLogEventLiveStream not found") from e

    # Private class has no bridgesupport metadata, so declare the block signatures.
    # The setters live on OSLogEventStreamBase, so register on NSObject to cover the hierarchy.
    def block(*arg_types: bytes) -> Dict[str, Any]:
        args = {0: {"type": b"^v"}}
        args.update({i + 1: {"type": t} for i, t in enumerate(arg_types)})
        return {"arguments": {2: {"callable": {"retval": {"type": b"v"}, "arguments": args}}}}

    objc.registerMetaDataForSelector(b"NSObject", b"setEventHandler:", block(b"@"))
    objc.registerMetaDataForSelector(b"NSObject", b"setInvalidationHandler:", block(b"q", b"@"))
    objc.registerMetaDataForSelector(b"NSObject", b"setDroppedEventHandler:", block(b"@"))
    return live_stream


def _str_or_none(val: Any) -> Any:
    return None if val is None else str(val)


def proxy_to_entry(proxy: Any) -> Dict[str, Any]:
    """Convert an OSLogEventProxy into the same shape `log --style ndjson` emits."""
    date = proxy.date()
    timestamp = ""
    if date is not None:
        timestamp = (
            datetime.fromtimestamp(date.timeIntervalSince1970())
            .astimezone()
            .strftime("%Y-%m-%d %H:%M:%S.%f%z")
        )
    return {
        "timestamp": timestamp,
        "messageType": _MESSAGE_TYPES.get(proxy.logType(), str(proxy.logType())),
        "eventType": "logEvent",
        "eventMessage": _str_or_none(proxy.composedMessage()) or "",
        "formatString": _str_or_none(proxy.formatString()),
        "subsystem": _str_or_none(proxy.subsystem()),
        "category": _str_or_none(proxy.category()),
        "processID": proxy.processIdentifier(),
        "processImagePath": _str_or_none(proxy.processImagePath()) or "",
        "processImageUUID": _str_or_none(proxy.processImageUUID()),
        "senderImagePath": _str_or_none(proxy.senderImagePath()),
        "userID": proxy.userIdentifier(),
        "threadID": proxy.threadIdentifier(),
        "activityIdentifier": proxy.activityIdentifier(),
        "parentActivityIdentifier": proxy.parentActivityIdentifier(),
        "traceID": proxy.traceIdentifier(),
    }


def iter_live_entries(predicate: str) -> Iterator[Dict[str, Any]]:
    """
    Yield live unified log entries matching `predicate` (debug level and above).

    Events are delivered on a LoggingSupport dispatch queue and handed to the
    caller's thread through a queue, so no run loop is needed. Closing the
    generator invalidates the stream.

    Raises NativeStreamUnavailable immediately (not on first iteration) if
    PyObjC or LoggingSupport can't be loaded.
    """
    return _iter_live_entries(_load_live_stream_class(), predicate)


def _iter_live_entries(live_stream: Any, predicate: str) -> Iterator[Dict[str, Any]]:
    from Foundation import NSPredicate

    events: "queue.Queue[Any]" = queue.Queue()

    def on_event(proxy: Any) -> None:
        try:
            events.put(proxy_to_entry(proxy))
        except Exception as e:  # never raise into the ObjC block
            print(f"aemonitor: failed to read log event: {e}", file=sys.stderr)

    def on_invalidated(reason: int, _stream: Any) -> None:
        events.put(_STOP)

    def on_dropped(info: Any) -> None:
        print(f"aemonitor: log events dropped: {info}", file=sys.stderr)

    stream = live_stream.alloc().init()
    stream.setFilterPredicate_(NSPredicate.predicateWithFormat_(predicate))
    stream.setFlags_(_LEVEL_DEBUG)
    stream.setEventHandler_(on_event)
    stream.setInvalidationHandler_(on_invalidated)
    stream.setDroppedEventHandler_(on_dropped)
    stream.activate()
    try:
        while True:
            try:
                # Short timeout keeps Ctrl+C responsive
                item = events.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is _STOP:
                return
            yield item
    finally:
        stream.invalidate()
