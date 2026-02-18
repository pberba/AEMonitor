import json
from pprint import pprint

from aemonitor import enrich_unified_log



apple_event_unified_log = '{"timezoneName":"","messageType":"Debug","eventType":"logEvent","source":null,"formatString":"%{public}ssendToSelf(), event=%{public}s reply=0x%{public}s sendMode=%x timeout=%ld","userID":501,"activityIdentifier":0,"subsystem":"com.apple.appleevents","category":"main","threadID":26558,"senderImageUUID":"9F093691-D69B-340A-8011-D9E096780C7E","backtrace":{"frames":[{"imageOffset":97964,"imageUUID":"9F093691-D69B-340A-8011-D9E096780C7E"}]},"bootUUID":"","processImagePath":"/usr/bin/osascript","senderImagePath":"/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE","timestamp":"2026-02-12 23:26:48.566432+0000","machTimestamp":21727813384,"eventMessage":"sendToSelf(), event={syso,exec target=\'psn \'[osascript] {----=utxt(32/$6b0069006c006c0061006c006c0020005400650072006d0069006e0061006c00...)} attr:{subj=NULL-impl,comp=8454145,scid=1,csig=65536} returnID=-27082} reply=0xNULL-impl sendMode=1043 timeout=7200","processImageUUID":"9F3FE279-8586-36D0-9E25-AD7CDD9921DC","traceID":575261752087020036,"processID":1819,"senderProgramCounter":97964,"parentActivityIdentifier":0}'
apple_event_unified_log_dict = json.loads(apple_event_unified_log)
enriched_log = enrich_unified_log(apple_event_unified_log_dict)
assert "appleEvent" in enriched_log
# The main fields used to enrich the log are:
# - eventMessage
# - processImagePath
# pprint(enrich_unified_log({
#     'eventMessage': apple_event_unified_log_dict['eventMessage'],
#     'processImagePath': apple_event_unified_log_dict['processImagePath']
# })["appleEvent"])

pprint(enriched_log["appleEvent"])


# Demonstrate that a log without an AppleEvent does not produce an enriched output.
none_apple_event_unified_log = (
    '{"timezoneName":"","messageType":"Debug","eventType":"logEvent","source":null,'
    '"formatString":"%{{public}}stryDescCoercion: coerce from %c%c%c%c => %c%c%c%c = %d/%s",'
    '"userID":501,"activityIdentifier":0,"subsystem":"com.apple.appleevents","category":"main",'
    '"threadID":26558,"senderImageUUID":"9F093691-D69B-340A-8011-D9E096780C7E","backtrace":{"frames":[{"imageOffset":52628,'
    '"imageUUID":"9F093691-D69B-340A-8011-D9E096780C7E"}]},"bootUUID":"","processImagePath":"/usr/bin/osascript",'
    '"senderImagePath":"/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/AE.framework/Versions/A/AE",'
    '"timestamp":"2026-02-12 23:26:48.571031+0000","machTimestamp":21727923752,'
    '"eventMessage":"        tryDescCoercion: coerce from shor => shor = -1700/-",'
    '"processImageUUID":"9F3FE279-8586-36D0-9E25-AD7CDD9921DC","traceID":575211505264624132,'
    '"processID":1819,"senderProgramCounter":52628,"parentActivityIdentifier":0}'
)
none_apple_event_unified_log_dict = json.loads(none_apple_event_unified_log)
result = enrich_unified_log(none_apple_event_unified_log_dict)
assert result is None
