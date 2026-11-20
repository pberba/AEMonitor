-- AEMonitor test: AppleScriptObjC bridge calls
--
-- Harmless, but it walks through the behaviour the objc.* indicators look for:
-- headless app made visible, region recon, a URL fetch, a password-style prompt
-- whose value is read as text and written to disk, a process launch and a call
-- to a class that doesn't exist.
--
-- Run:  osascript example/objc_demo.applescript
-- When the dialog asks, type a throwaway value, NOT a real password: it is logged
-- in cleartext and AEMonitor shows it as is.

use AppleScript version "2.4"
use framework "Foundation"
use framework "AppKit"
use scripting additions

-- objc.ui.headless_to_gui: osascript has no UI until it becomes a regular app
set nsApp to current application's NSApplication's sharedApplication()
nsApp's setActivationPolicy:(current application's NSApplicationActivationPolicyRegular)
nsApp's activateIgnoringOtherApps:true

-- objc.recon.region: locale, time zone and keyboard layouts
set localeID to (current application's NSLocale's currentLocale()'s localeIdentifier()) as text
set tzName to (current application's NSTimeZone's systemTimeZone()'s |name|()) as text
set defaults to current application's NSUserDefaults's standardUserDefaults()
set keyboard to defaults's persistentDomainForName:"com.apple.HIToolbox"

-- objc.net.url, objc.net.session: a plain GET
set theURL to current application's NSURL's URLWithString:"https://example.com"
set pageData to current application's NSData's dataWithContentsOfURL:theURL

-- objc.cred.*: an alert with a secure text field, raised above other windows
set field to current application's NSSecureTextField's alloc()'s initWithFrame:{{0, 0}, {260, 24}}
set alert to current application's NSAlert's alloc()'s init()
alert's setMessageText:"AEMonitor test"
alert's setInformativeText:"Type any throwaway text (not a real password)."
alert's addButtonWithTitle:"OK"
alert's addButtonWithTitle:"Cancel"
alert's setAccessoryView:field
alert's |window|()'s setLevel:(current application's NSStatusWindowLevel)
alert's |window|()'s setInitialFirstResponder:field
set answer to alert's runModal()

-- objc.cred.cleartext_leak: coercing the field's value to text logs it
set typed to (field's stringValue()) as text

-- objc.cred.saved_to_disk, objc.file.stage: written to /tmp, then removed
set outPath to "/tmp/aemonitor-objc-demo.txt"
set nsText to current application's NSString's stringWithString:typed
nsText's writeToFile:outPath atomically:true encoding:(current application's NSUTF8StringEncoding) |error|:(missing value)
current application's NSFileManager's defaultManager()'s removeItemAtPath:outPath |error|:(missing value)

-- objc.exec.task: launches /usr/bin/true
current application's NSTask's launchedTaskWithLaunchPath:"/usr/bin/true" arguments:{}

-- objc.bridge.failed_lookup: a class that doesn't exist
try
	current application's AEMonitorNoSuchClass's new()
end try

display dialog "Done: " & localeID & ", " & tzName & ", typed " & (count typed) & " characters." buttons {"OK"} default button 1
