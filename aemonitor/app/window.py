"""
Native macOS app for aemonitor (AppKit via PyObjC): a live event table with sidebar
filters and a detail pane, plus Start/Stop, open, export and muting. Requires the
`native` extra. Run with `python -m aemonitor.app`; see AEMonitor.spec to build AEMonitor.app.
"""

import json
import os
import sys
from datetime import datetime
from typing import Any, List, Optional, Tuple

import objc
from AppKit import (
    NSAlert,
    NSAlertFirstButtonReturn,
    NSApplication,
    NSApplicationActivationPolicyRegular,
    NSAttributedString,
    NSBackingStoreBuffered,
    NSButton,
    NSColor,
    NSCompositingOperationSourceOver,
    NSFont,
    NSFontAttributeName,
    NSForegroundColorAttributeName,
    NSImage,
    NSMakeRect,
    NSMenu,
    NSMenuItem,
    NSModalResponseOK,
    NSMutableAttributedString,
    NSMutableParagraphStyle,
    NSParagraphStyleAttributeName,
    NSOpenPanel,
    NSSavePanel,
    NSScrollView,
    NSSearchToolbarItem,
    NSSplitView,
    NSSplitViewController,
    NSSplitViewItem,
    NSStringDrawingUsesLineFragmentOrigin,
    NSRectFillUsingOperation,
    NSStackView,
    NSTabView,
    NSTabViewItem,
    NSTableColumn,
    NSTableHeaderView,
    NSTableRowView,
    NSTableView,
    NSTableViewStyleSourceList,
    NSTextField,
    NSTextView,
    NSToolbar,
    NSToolbarFlexibleSpaceItemIdentifier,
    NSToolbarItem,
    NSView,
    NSViewController,
    NSViewHeightSizable,
    NSViewWidthSizable,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
    NSWindowToolbarStyleUnified,
    NSWorkspace,
)
from Foundation import NSIndexSet, NSMutableIndexSet, NSNotFound, NSObject, NSTimer, NSUserDefaults

from aemonitor.app.model import (
    FACETS,
    INDICATORS,
    INDICATORS_BY_ID,
    PRIVACY_MODES,
    EventStore,
    Monitor,
    Row,
    RowFilter,
    applescript_tokens,
)

LOG_PATH = os.path.expanduser("~/Library/Logs/AEMonitor.log")

# View > Logging Privacy: which logging configuration the table simulates.
PRIVACY_MENU = (
    ("private", "Enabled Private Data"),  # Enable-Private-Data: everything
    ("public", "Set Default to Public"),  # Default-Privacy-Setting: Public; hides %{private}
    ("default", "Default macOS Settings"),  # stock: %{public} only
)
PRIVACY_STATUS = dict(PRIVACY_MENU)
del PRIVACY_STATUS["private"]  # nothing redacted, so no status note
MUTED_DEFAULTS_KEY = "MutedValues"
WRAP_DEFAULTS_KEY = "WrapLongLines"
WRAPPING_COLUMNS = ("script", "reply")
ROW_HEIGHT = 20
DRAIN_SECONDS = 0.25
FACET_LIMIT = 40

# (identifier, title, width)
EVENT_COLUMNS = [
    ("sev", "", 18),
    ("time", "Time", 96),
    ("pid", "PID", 56),
    ("process", "Process", 120),
    ("target", "Target", 110),
    ("code", "Event", 80),
    ("script", "AppleScript", 420),
    ("reply", "Reply", 220),
]
DEFAULT_COLUMN_WIDTHS = {ident: width for ident, _title, width in EVENT_COLUMNS}
SIDEBAR_SECTIONS = [
    ("indicator", "Indicators"),
    ("process", "Processes"),
    ("target", "Targets"),
    ("code", "Events"),
]

_MONO = NSFont.monospacedSystemFontOfSize_weight_(11, 0)
_MONO_BOLD = NSFont.monospacedSystemFontOfSize_weight_(11, 0.4)


def _severity_color(severity: str):
    return {
        "high": NSColor.systemRedColor(),
        "medium": NSColor.systemOrangeColor(),
        "low": NSColor.systemBlueColor(),
    }.get(severity, NSColor.secondaryLabelColor())


def _symbol(name: str, fallback_title: str):
    return NSImage.imageWithSystemSymbolName_accessibilityDescription_(name, fallback_title)


def _label(text: str = "", font=None, color=None) -> NSTextField:
    field = NSTextField.labelWithString_(text)
    field.setLineBreakMode_(4)  # NSLineBreakByTruncatingTail
    if font is not None:
        field.setFont_(font)
    if color is not None:
        field.setTextColor_(color)
    return field


def _padded(views, top: float = 3, bottom: float = 3) -> NSStackView:
    """A horizontal stack of views with vertical padding, for sidebar rows."""
    stack = NSStackView.stackViewWithViews_(views)
    stack.setSpacing_(6)
    stack.setEdgeInsets_((top, 2, bottom, 2))
    return stack


def _index_list(index_set) -> List[int]:
    """The indexes in an NSIndexSet (which ends with NSNotFound, not -1)."""
    out = []
    i = index_set.firstIndex()
    while i != NSNotFound:
        out.append(i)
        i = index_set.indexGreaterThanIndex_(i)
    return out


def _scrolling_text_view() -> Tuple[NSScrollView, NSTextView]:
    scroll = NSTextView.scrollableTextView()
    text = scroll.documentView()
    text.setEditable_(False)
    text.setRichText_(True)
    text.setFont_(_MONO)
    text.setTextContainerInset_((8, 8))
    return scroll, text


def _syntax_color(name, light, dark):
    """A syntax color that adapts to the current appearance (r, g, b in 0..1).

    The name must be UNIQUE per color: when stored as a text attribute, AppKit
    re-resolves named colors through the shared catalog by name at draw time, so a
    duplicate name would make every token render with one color.
    """
    def provider(appearance, light=light, dark=dark):
        rgb = dark if "Dark" in str(appearance.name()) else light
        return NSColor.colorWithSRGBRed_green_blue_alpha_(rgb[0], rgb[1], rgb[2], 1.0)

    return NSColor.colorWithName_dynamicProvider_("aemSyntax_" + name, provider)


# Sublime Text's default scheme (Monokai). Dark-mode values are the exact Monokai
# colors; light-mode values are darkened so they stay legible on the white rows.
_SYNTAX_COLORS = {
    "keyword": _syntax_color("keyword", (0.80, 0.08, 0.38), (0.976, 0.149, 0.447)),  # pink   #F92672
    "command": _syntax_color("command", (0.10, 0.52, 0.62), (0.400, 0.851, 0.937)),  # cyan   #66D9EF
    "label": _syntax_color("label", (0.80, 0.42, 0.00), (0.992, 0.592, 0.122)),      # orange #FD971F
    "string": _syntax_color("string", (0.55, 0.48, 0.05), (0.902, 0.859, 0.455)),    # yellow #E6DB74
    "number": _syntax_color("number", (0.46, 0.28, 0.80), (0.682, 0.506, 1.000)),    # purple #AE81FF
    "comment": _syntax_color("comment", (0.45, 0.44, 0.37), (0.459, 0.443, 0.369)),  # gray   #75715E
}

_TRUNCATING = NSMutableParagraphStyle.alloc().init()
_TRUNCATING.setLineBreakMode_(4)  # NSLineBreakByTruncatingTail


class _Attributed:
    """Small builder for attributed text in the detail pane and the AppleScript column."""

    def __init__(self, paragraph=None) -> None:
        self.text = NSMutableAttributedString.alloc().init()
        self.paragraph = paragraph

    def add(self, s: str, font=_MONO, color=None) -> "_Attributed":
        attrs = {NSFontAttributeName: font, NSForegroundColorAttributeName: color or NSColor.labelColor()}
        if self.paragraph is not None:
            attrs[NSParagraphStyleAttributeName] = self.paragraph
        self.text.appendAttributedString_(NSAttributedString.alloc().initWithString_attributes_(s, attrs))
        return self

    def applescript(self, s: str) -> "_Attributed":
        """Append s with basic AppleScript syntax colors."""
        pos = 0
        for start, end, kind in applescript_tokens(s):
            if start > pos:
                self.add(s[pos:start])
            self.add(s[start:end], _MONO, _SYNTAX_COLORS[kind])
            pos = end
        if pos < len(s):
            self.add(s[pos:])
        return self

    def section(self, title: str, body: Optional[str], *, highlight: bool = False) -> "_Attributed":
        if body:
            self.add(title + "\n", _MONO_BOLD, NSColor.systemOrangeColor())
            if highlight:
                self.applescript(body)
            else:
                self.add(body)
            self.add("\n\n")
        return self


_RELATED_COLOR = NSColor.systemYellowColor().colorWithAlphaComponent_(0.16)


class _EventRowView(NSTableRowView):
    """Table row view that tints rows correlated with the selection (same thread+returnID)."""

    def drawBackgroundInRect_(self, rect):
        objc.super(_EventRowView, self).drawBackgroundInRect_(rect)
        if getattr(self, "_related", False) and not self.isSelected():
            _RELATED_COLOR.set()
            NSRectFillUsingOperation(rect, NSCompositingOperationSourceOver)


class _EventHeaderView(NSTableHeaderView):
    """Header view that toggles a column between fit-to-content and its default width
    on a double-click of the header (not the resize divider)."""

    def mouseDown_(self, event):
        if event.clickCount() == 2:
            point = self.convertPoint_fromView_(event.locationInWindow(), None)
            col = self.columnAtPoint_(point)
            handler = getattr(self, "_handler", None)
            if col >= 0 and handler is not None:
                handler.toggleColumnWidth_(col)
                return
        objc.super(_EventHeaderView, self).mouseDown_(event)


class AppDelegate(NSObject):
    # -- setup ----------------------------------------------------------------

    def applicationDidFinishLaunching_(self, _notification) -> None:
        self.store = EventStore()
        self.filter = RowFilter()
        self.filter.muted = self._load_muted()
        self.monitor = Monitor()
        self.filtered: List[Row] = []
        self.visible_ids = set()
        self.related_ids = set()
        self.sidebar_entries: List[Tuple[str, str, str, int]] = []
        self.updating_sidebar = False
        self.sidebar_click_selection = None
        self.wrap_lines = bool(NSUserDefaults.standardUserDefaults().boolForKey_(WRAP_DEFAULTS_KEY))
        self.wrapped_heights = {}  # (row id, reply text, column widths) -> height
        self.counts_dirty = True

        self._build_menu()
        self._build_window()
        self.timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            DRAIN_SECONDS, self, "drain:", None, True
        )
        self.startMonitoring_(None)
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

    def applicationShouldTerminateAfterLastWindowClosed_(self, _app) -> bool:
        return True

    def applicationWillTerminate_(self, _notification) -> None:
        self.monitor.stop()

    @objc.python_method
    def _build_menu(self) -> None:
        def item(menu, title, action, key="", target=None):
            mi = menu.addItemWithTitle_action_keyEquivalent_(title, action, key)
            if target is not None:
                mi.setTarget_(target)
            return mi

        app = NSApplication.sharedApplication()
        main = NSMenu.alloc().init()

        def submenu(title):
            top = main.addItemWithTitle_action_keyEquivalent_(title, None, "")
            menu = NSMenu.alloc().initWithTitle_(title)
            top.setSubmenu_(menu)
            return menu

        m = submenu("AEMonitor")
        item(m, "About AEMonitor", "orderFrontStandardAboutPanel:")
        m.addItem_(NSMenuItem.separatorItem())
        item(m, "Show Log", "showLog:", "", self)
        m.addItem_(NSMenuItem.separatorItem())
        item(m, "Hide AEMonitor", "hide:", "h")
        item(m, "Quit AEMonitor", "terminate:", "q")

        m = submenu("File")
        item(m, "Open Log Archive or NDJSON…", "openDocument:", "o", self)
        item(m, "Export Shown Events…", "exportEvents:", "s", self)
        m.addItem_(NSMenuItem.separatorItem())
        item(m, "Close Window", "performClose:", "w")

        m = submenu("Edit")
        item(m, "Copy", "copy:", "c")
        item(m, "Select All", "selectAll:", "a")
        m.addItem_(NSMenuItem.separatorItem())
        item(m, "Find", "focusSearch:", "f", self)

        m = submenu("Monitor")
        self.toggle_menu_item = item(m, "Stop", "toggleMonitoring:", "r", self)
        item(m, "Clear Events", "clearEvents:", "k", self)

        m = submenu("View")
        self.flagged_menu_item = item(m, "Flagged Only", "toggleFlaggedOnly:", "F", self)
        self.clones_menu_item = item(m, "Show Clone Events", "toggleClones:", "", self)
        self.clones_menu_item.setState_(1)
        privacy_top = m.addItemWithTitle_action_keyEquivalent_("Logging Privacy", None, "")
        privacy_menu = NSMenu.alloc().initWithTitle_("Logging Privacy")
        privacy_top.setSubmenu_(privacy_menu)
        self.privacy_menu_items = {}
        for mode, title in PRIVACY_MENU:
            mi = item(privacy_menu, title, "setPrivacyMode:", "", self)
            mi.setRepresentedObject_(mode)
            self.privacy_menu_items[mode] = mi
        self._update_privacy_menu()
        item(m, "Clear Filters", "clearFilters:", "l", self)
        m.addItem_(NSMenuItem.separatorItem())
        self.wrap_menu_item = item(m, "Wrap Long Lines", "toggleWrap:", "", self)
        self.wrap_menu_item.setState_(int(self.wrap_lines))
        m.addItem_(NSMenuItem.separatorItem())
        item(m, "Reset Muted Values", "unmuteAll:", "", self)

        m = submenu("Window")
        item(m, "Minimize", "performMiniaturize:", "m")
        app.setWindowsMenu_(m)

        app.setMainMenu_(main)

    @objc.python_method
    def _build_window(self) -> None:
        style = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskMiniaturizable
            | NSWindowStyleMaskResizable
        )
        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 1280, 780), style, NSBackingStoreBuffered, False
        )
        self.window.setTitle_("AEMonitor")
        self.window.setMinSize_((800, 480))
        self.window.setFrameAutosaveName_("AEMonitorMain")

        split = NSSplitViewController.alloc().init()
        sidebar_vc = NSViewController.alloc().init()
        sidebar_vc.setView_(self._build_sidebar())
        sidebar_item = NSSplitViewItem.sidebarWithViewController_(sidebar_vc)
        sidebar_item.setMinimumThickness_(180)
        sidebar_item.setMaximumThickness_(320)
        split.addSplitViewItem_(sidebar_item)

        main_vc = NSViewController.alloc().init()
        main_vc.setView_(self._build_main())
        split.addSplitViewItem_(NSSplitViewItem.splitViewItemWithViewController_(main_vc))

        self.window.setContentViewController_(split)
        self.window.setContentSize_((1280, 780))
        self.window.center()

        toolbar = NSToolbar.alloc().initWithIdentifier_("AEMonitorToolbar")
        toolbar.setDelegate_(self)
        toolbar.setDisplayMode_(1)  # icon and label
        self.window.setToolbar_(toolbar)
        self.window.setToolbarStyle_(NSWindowToolbarStyleUnified)
        self.window.makeKeyAndOrderFront_(None)
        self.detail_split.setPosition_ofDividerAtIndex_(self.detail_split.frame().size.height * 0.6, 0)

    @objc.python_method
    def _build_sidebar(self) -> NSView:
        table = NSTableView.alloc().init()
        # Assigned before setDataSource_, which queries the row count right away
        self.sidebar_table = table
        table.setStyle_(NSTableViewStyleSourceList)
        table.setHeaderView_(None)
        table.setFloatsGroupRows_(False)
        table.setAllowsMultipleSelection_(True)
        table.setAllowsEmptySelection_(True)
        # Clicking the only selected entry again deselects it (see sidebarClicked_)
        table.setTarget_(self)
        table.setAction_("sidebarClicked:")
        column = NSTableColumn.alloc().initWithIdentifier_("facet")
        column.setResizingMask_(1)  # autoresizing
        table.addTableColumn_(column)
        table.setDataSource_(self)
        table.setDelegate_(self)
        menu = NSMenu.alloc().init()
        menu.setDelegate_(self)
        table.setMenu_(menu)

        scroll = NSScrollView.alloc().init()
        scroll.setDocumentView_(table)
        scroll.setHasVerticalScroller_(True)
        scroll.setDrawsBackground_(False)
        return scroll

    @objc.python_method
    def _build_main(self) -> NSView:
        container = NSView.alloc().initWithFrame_(NSMakeRect(0, 0, 1000, 780))

        table = NSTableView.alloc().init()
        self.events_table = table
        table.setUsesAlternatingRowBackgroundColors_(True)
        table.setAllowsMultipleSelection_(False)
        table.setRowHeight_(ROW_HEIGHT)
        for ident, title, width in EVENT_COLUMNS:
            column = NSTableColumn.alloc().initWithIdentifier_(ident)
            column.setTitle_(title)
            column.setWidth_(width)
            column.setMinWidth_(18 if ident == "sev" else 40)
            column.setMaxWidth_(10000)
            if ident == "sev":
                column.setResizingMask_(0)
            table.addTableColumn_(column)
        # Columns keep the widths you drag them to; the table scrolls sideways when wider
        table.setColumnAutoresizingStyle_(0)  # NSTableViewNoColumnAutoresizing
        # Double-click a header to fit the column to its content, again to restore default
        header = _EventHeaderView.alloc().init()
        header._handler = self
        table.setHeaderView_(header)
        table.setAutosaveName_("AEMonitorEvents")
        table.setAutosaveTableColumns_(True)
        table.setDataSource_(self)
        table.setDelegate_(self)
        menu = NSMenu.alloc().init()
        menu.setDelegate_(self)
        table.setMenu_(menu)

        table_scroll = NSScrollView.alloc().init()
        table_scroll.setDocumentView_(table)
        table_scroll.setHasVerticalScroller_(True)
        table_scroll.setHasHorizontalScroller_(True)
        self.table_scroll = table_scroll

        tabs = NSTabView.alloc().init()
        self.detail_views = {}
        for ident, title in (("overview", "Overview"), ("raw", "Raw"), ("json", "JSON")):
            scroll, text = _scrolling_text_view()
            tab = NSTabViewItem.alloc().initWithIdentifier_(ident)
            tab.setLabel_(title)
            tab.setView_(scroll)
            tabs.addTabViewItem_(tab)
            self.detail_views[ident] = text

        split = NSSplitView.alloc().initWithFrame_(NSMakeRect(0, 24, 1000, 756))
        split.setVertical_(False)
        split.setDividerStyle_(2)  # thin
        split.addSubview_(table_scroll)
        split.addSubview_(tabs)
        split.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        split.adjustSubviews()
        self.detail_split = split

        status = _label("", NSFont.systemFontOfSize_(11), NSColor.secondaryLabelColor())
        status.setFrame_(NSMakeRect(10, 4, 980, 16))
        status.setAutoresizingMask_(NSViewWidthSizable)
        self.status_label = status

        container.addSubview_(split)
        container.addSubview_(status)
        self._show_detail(None)
        return container

    # -- toolbar --------------------------------------------------------------

    def toolbarDefaultItemIdentifiers_(self, _toolbar):
        return ["toggle", "clear", "flagged", "clearFilters", NSToolbarFlexibleSpaceItemIdentifier, "search"]

    def toolbarAllowedItemIdentifiers_(self, toolbar):
        return self.toolbarDefaultItemIdentifiers_(toolbar)

    def toolbar_itemForItemIdentifier_willBeInsertedIntoToolbar_(self, _toolbar, ident, _insert):
        if ident == "search":
            item = NSSearchToolbarItem.alloc().initWithItemIdentifier_(ident)
            field = item.searchField()
            field.setPlaceholderString_("Filter: text, pid:123 proc:osascript target:Finder code:syso,exec flag:high")
            field.setDelegate_(self)
            item.setPreferredWidthForSearchField_(420)
            self.search_field = field
            return item

        item = NSToolbarItem.alloc().initWithItemIdentifier_(ident)
        item.setTarget_(self)
        item.setBordered_(True)
        if ident == "toggle":
            item.setAction_("toggleMonitoring:")
            self.toggle_item = item
            self._update_toggle()
        elif ident == "clear":
            item.setLabel_("Clear")
            item.setToolTip_("Clear the table")
            item.setImage_(_symbol("trash", "Clear"))
            item.setAction_("clearEvents:")
        elif ident == "flagged":
            item.setLabel_("Flagged Only")
            item.setToolTip_("Show only events that match an indicator")
            item.setImage_(_symbol("flag", "Flagged Only"))
            item.setAction_("toggleFlaggedOnly:")
            self.flagged_item = item
        elif ident == "clearFilters":
            item.setLabel_("Clear Filters")
            item.setToolTip_("Clear the search, sidebar selection and Flagged Only (⌘L)")
            item.setImage_(_symbol("line.3.horizontal.decrease.circle", "Clear Filters"))
            item.setAction_("clearFilters:")
        return item

    @objc.python_method
    def _update_toggle(self) -> None:
        running = self.monitor.running and not self.monitor.source
        title = "Stop" if running else "Start"
        if hasattr(self, "toggle_item"):
            self.toggle_item.setLabel_(title)
            self.toggle_item.setToolTip_(f"{title} live monitoring (⌘R)")
            self.toggle_item.setImage_(_symbol("stop.fill" if running else "play.fill", title))
        self.toggle_menu_item.setTitle_(f"{title} Monitoring")

    # -- monitoring -------------------------------------------------------------

    @objc.IBAction
    def startMonitoring_(self, _sender) -> None:
        try:
            self.monitor.start()
        except OSError as e:
            self._alert("Could not start monitoring", str(e))
        self._update_toggle()
        self._update_status()

    @objc.IBAction
    def toggleMonitoring_(self, _sender) -> None:
        if self.monitor.running and not self.monitor.source:
            self.monitor.stop()
            self._update_toggle()
            self._update_status()
        else:
            if self.monitor.source:
                # Switching from a loaded file back to live: start with a fresh table
                self._clear()
            self.startMonitoring_(None)

    def drain_(self, _timer) -> None:
        records = self.monitor.drain()
        if records:
            self._ingest(records)
        if self.counts_dirty:
            self._reload_sidebar()
        self._update_toggle()
        self._update_status()

    @objc.python_method
    def _ingest(self, records) -> None:
        table = self.events_table
        clip = self.table_scroll.contentView()
        doc_height = table.frame().size.height
        at_bottom = clip.bounds().origin.y + clip.bounds().size.height >= doc_height - 2 * table.rowHeight()

        refilter = False
        changed: List[int] = []
        for record in records:
            row, is_new = self.store.add(record)
            visible = self.filter.matches(row)
            if is_new:
                if visible:
                    self.filtered.append(row)
                    self.visible_ids.add(row.id)
            elif visible != (row.id in self.visible_ids):
                refilter = True
            elif visible:
                changed.append(row.id)
        self.counts_dirty = True

        if refilter:
            self._refilter()
        else:
            table.noteNumberOfRowsChanged()
            if changed:
                ids = set(changed)
                indexes = NSMutableIndexSet.indexSet()
                # Replies land near the end, so search from there
                for i in range(len(self.filtered) - 1, -1, -1):
                    if self.filtered[i].id in ids:
                        indexes.addIndex_(i)
                        ids.discard(self.filtered[i].id)
                        if not ids:
                            break
                table.reloadDataForRowIndexes_columnIndexes_(
                    indexes, NSIndexSet.indexSetWithIndexesInRange_((0, len(EVENT_COLUMNS)))
                )
                selected = self._selected_row()
                if selected is not None and selected.id in changed:
                    self._show_detail(selected)
        if at_bottom and self.filtered:
            table.scrollRowToVisible_(len(self.filtered) - 1)

    @objc.python_method
    def _refilter(self) -> None:
        selected = self._selected_row()
        self.filtered = [r for r in self.store.rows if self.filter.matches(r)]
        self.visible_ids = {r.id for r in self.filtered}
        self.events_table.reloadData()
        if selected is not None and selected.id in self.visible_ids:
            index = self.filtered.index(selected)
            self.events_table.selectRowIndexes_byExtendingSelection_(NSIndexSet.indexSetWithIndex_(index), False)
            self.events_table.scrollRowToVisible_(index)
        else:
            self._show_detail(None)
        self._update_status()

    @objc.python_method
    def _update_status(self) -> None:
        m = self.monitor
        if m.source:
            state = f"{os.path.basename(m.source)} ({'loading' if m.running else 'loaded'})"
        elif m.running:
            state = f"Monitoring ({m.backend})"
        elif m.exit_code:
            state = f"Stopped: log stream exited with {m.exit_code} (see Show Log)"
        else:
            state = "Stopped"
        text = f"{state} · {len(self.store.rows):,} events · {len(self.filtered):,} shown"
        mode = self.filter.privacy_mode
        if mode in PRIVACY_STATUS:
            revealed = PRIVACY_MODES[mode]
            hidden = sum(1 for r in self.store.rows if r.privacy not in revealed)
            text += f" · {PRIVACY_STATUS[mode]} ({hidden:,} redacted)"
        if self.store.private_data_seen:
            text += " · some fields are <private>: enable private data in unified logs to see full events"
        self.status_label.setStringValue_(text)

    @objc.python_method
    def _clear(self) -> None:
        self.store.clear()
        self.filtered = []
        self.visible_ids = set()
        self.events_table.reloadData()
        self.counts_dirty = True
        self._show_detail(None)

    @objc.IBAction
    def clearEvents_(self, _sender) -> None:
        self._clear()
        self._update_status()

    # -- filters --------------------------------------------------------------

    def controlTextDidChange_(self, notification) -> None:
        self.filter.set_query(notification.object().stringValue())
        self._refilter()

    @objc.IBAction
    def focusSearch_(self, _sender) -> None:
        if hasattr(self, "search_field"):
            self.window.makeFirstResponder_(self.search_field)

    @objc.IBAction
    def toggleFlaggedOnly_(self, _sender) -> None:
        self.filter.only_flagged = not self.filter.only_flagged
        self.flagged_menu_item.setState_(int(self.filter.only_flagged))
        if hasattr(self, "flagged_item"):
            self.flagged_item.setImage_(_symbol("flag.fill" if self.filter.only_flagged else "flag", "Flagged Only"))
        self._refilter()

    @objc.IBAction
    def clearFilters_(self, _sender) -> None:
        self.filter.include = {f: set() for f in FACETS}
        self.filter.set_query("")
        if hasattr(self, "search_field"):
            self.search_field.setStringValue_("")
        if self.filter.only_flagged:
            self.toggleFlaggedOnly_(None)
        self.updating_sidebar = True
        try:
            self.sidebar_table.deselectAll_(None)
        finally:
            self.updating_sidebar = False
        self.sidebar_click_selection = None
        self._refilter()

    @objc.IBAction
    def sidebarClicked_(self, sender) -> None:
        index = sender.clickedRow()
        selected = set(_index_list(sender.selectedRowIndexes()))
        if index >= 0 and selected == {index} and self.sidebar_click_selection == {index}:
            sender.deselectAll_(None)  # triggers tableViewSelectionDidChange_, which refilters
            selected = set()
        self.sidebar_click_selection = selected

    @objc.IBAction
    def toggleWrap_(self, _sender) -> None:
        self.wrap_lines = not self.wrap_lines
        NSUserDefaults.standardUserDefaults().setBool_forKey_(self.wrap_lines, WRAP_DEFAULTS_KEY)
        self.wrap_menu_item.setState_(int(self.wrap_lines))
        table = self.events_table
        table.reloadData()
        table.noteHeightOfRowsWithIndexesChanged_(
            NSIndexSet.indexSetWithIndexesInRange_((0, len(self.filtered)))
        )

    @objc.IBAction
    def toggleClones_(self, _sender) -> None:
        self.filter.show_clones = not self.filter.show_clones
        self.clones_menu_item.setState_(int(self.filter.show_clones))
        self._refilter()

    @objc.IBAction
    def setPrivacyMode_(self, sender) -> None:
        # Show only what a Mac with this logging configuration would record: events
        # whose payload it redacts can't be parsed there, so they'd never appear.
        self.filter.privacy_mode = str(sender.representedObject())
        self._update_privacy_menu()
        self._refilter()
        self._update_status()

    @objc.python_method
    def _update_privacy_menu(self) -> None:
        for mode, mi in self.privacy_menu_items.items():
            mi.setState_(int(mode == self.filter.privacy_mode))

    @objc.python_method
    def _mute(self, facet: str, value: str) -> None:
        self.filter.muted.add((facet, value))
        self.filter.include[facet].discard(value)
        self._save_muted()
        self.counts_dirty = True
        self._refilter()

    @objc.python_method
    def _unmute(self, facet: str, value: str) -> None:
        self.filter.muted.discard((facet, value))
        self._save_muted()
        self.counts_dirty = True
        self._refilter()

    @objc.IBAction
    def unmuteAll_(self, _sender) -> None:
        self.filter.muted.clear()
        self._save_muted()
        self.counts_dirty = True
        self._refilter()

    @objc.python_method
    def _load_muted(self):
        values = NSUserDefaults.standardUserDefaults().stringArrayForKey_(MUTED_DEFAULTS_KEY) or []
        muted = set()
        for v in values:
            facet, _, value = str(v).partition("\t")
            if facet in FACETS and value:
                muted.add((facet, value))
        return muted

    @objc.python_method
    def _save_muted(self) -> None:
        NSUserDefaults.standardUserDefaults().setObject_forKey_(
            sorted(f"{f}\t{v}" for f, v in self.filter.muted), MUTED_DEFAULTS_KEY
        )

    # -- sidebar --------------------------------------------------------------

    @objc.python_method
    def _reload_sidebar(self) -> None:
        self.counts_dirty = False
        entries: List[Tuple[str, str, str, int]] = []  # (kind, facet, key, count)
        for facet, title in SIDEBAR_SECTIONS:
            entries.append(("header", facet, title, 0))
            counts = self.store.counts[facet]
            if facet == "indicator":
                keys = [(i.id, counts[i.id]) for i in INDICATORS if counts.get(i.id)]
            else:
                keys = counts.most_common(FACET_LIMIT)
            entries.extend(("item", facet, key, n) for key, n in keys if (facet, key) not in self.filter.muted)
        if self.filter.muted:
            entries.append(("header", "", "Muted", 0))
            entries.extend(("muted", f, v, 0) for f, v in sorted(self.filter.muted))
        if entries == self.sidebar_entries:
            return

        self.sidebar_entries = entries
        self.updating_sidebar = True
        try:
            self.sidebar_table.reloadData()
            selection = NSMutableIndexSet.indexSet()
            for i, (kind, facet, key, _n) in enumerate(entries):
                if kind == "item" and key in self.filter.include[facet]:
                    selection.addIndex_(i)
            self.sidebar_table.selectRowIndexes_byExtendingSelection_(selection, False)
        finally:
            self.updating_sidebar = False
        self.sidebar_click_selection = None
        self.wrap_lines = bool(NSUserDefaults.standardUserDefaults().boolForKey_(WRAP_DEFAULTS_KEY))
        self.wrapped_heights = {}  # (row id, reply text, column widths) -> height

    @objc.python_method
    def _sidebar_view(self, index: int) -> NSView:
        kind, facet, key, n = self.sidebar_entries[index]
        if kind == "header":
            label = _label(key.upper(), NSFont.boldSystemFontOfSize_(10), NSColor.secondaryLabelColor())
            return _padded([label], top=20 if index == 0 else 14, bottom=4)
        if kind == "muted":
            return _padded([_label(f"{facet}: {key}", NSFont.systemFontOfSize_(12), NSColor.tertiaryLabelColor())])

        views = []
        name = key
        if facet == "indicator":
            ind = INDICATORS_BY_ID[key]
            dot = _label("●", NSFont.systemFontOfSize_(9), _severity_color(ind.severity))
            views.append(dot)
            name = ind.label
        title = _label(name, NSFont.systemFontOfSize_(12))
        title.setToolTip_(INDICATORS_BY_ID[key].tactic if facet == "indicator" else key)
        title.setContentCompressionResistancePriority_forOrientation_(250, 0)
        count = _label(f"{n:,}", NSFont.monospacedDigitSystemFontOfSize_weight_(11, 0), NSColor.secondaryLabelColor())
        count.setContentHuggingPriority_forOrientation_(750, 0)
        views.extend([title, count])
        return _padded(views)

    # -- table data source / delegate (both tables) -----------------------------

    def numberOfRowsInTableView_(self, table) -> int:
        if table == self.sidebar_table:
            return len(self.sidebar_entries)
        return len(self.filtered)

    def tableView_viewForTableColumn_row_(self, table, column, index):
        if table == self.sidebar_table:
            return self._sidebar_view(index)

        row = self.filtered[index]
        ident = column.identifier()
        wrap = self.wrap_lines and ident in WRAPPING_COLUMNS
        reuse_id = f"{ident}.wrap" if wrap else ident
        field = table.makeViewWithIdentifier_owner_(reuse_id, self)
        if field is None:
            field = NSTextField.wrappingLabelWithString_("") if wrap else _label("")
            field.setFont_(_MONO)
            field.setIdentifier_(reuse_id)
            if wrap:
                # wrappingLabel is selectable; keep the field editor rich so a
                # double-click selection doesn't drop the syntax colors
                field.setAllowsEditingTextAttributes_(True)
        if ident in WRAPPING_COLUMNS:
            field.setAttributedStringValue_(self._cell_text(row, ident, wrap))
            field.setToolTip_((row.script or row.reply_text) if ident == "script" else (row.reply_text or None))
            return field
        color = NSColor.labelColor()
        text, tip = "", None
        if ident == "sev":
            text = "●" if row.severity else ""
            color = _severity_color(row.severity)
            tip = ", ".join(f.label for f in row.flags) or None
        elif ident == "time":
            text, tip = row.timestamp[11:23], row.timestamp
            color = NSColor.secondaryLabelColor()
        elif ident == "pid":
            text = str(row.pid)
            color = NSColor.secondaryLabelColor()
        elif ident == "process":
            text, tip = row.process, row.process_path
        elif ident == "target":
            text = row.target or "—"
        elif ident == "code":
            text = row.code
            color = NSColor.secondaryLabelColor()
        field.setStringValue_(text)
        field.setTextColor_(color)
        field.setToolTip_(tip)
        return field

    def tableViewColumnDidResize_(self, notification) -> None:
        if self.wrap_lines and notification.object() == self.events_table:
            column = notification.userInfo()["NSTableColumn"]
            if column.identifier() in WRAPPING_COLUMNS:
                self.events_table.noteHeightOfRowsWithIndexesChanged_(
                    NSIndexSet.indexSetWithIndexesInRange_((0, len(self.filtered)))
                )

    def tableView_heightOfRow_(self, table, index) -> float:
        if table == self.sidebar_table:
            # Sidebar rows size to their padded content
            return self._sidebar_view(index).fittingSize().height
        if not self.wrap_lines or index >= len(self.filtered):
            return ROW_HEIGHT
        row = self.filtered[index]
        widths = tuple(table.tableColumnWithIdentifier_(i).width() for i in WRAPPING_COLUMNS)
        key = (row.id, row.reply_text, widths)
        height = self.wrapped_heights.get(key)
        if height is None:
            height = ROW_HEIGHT
            for ident, width in zip(WRAPPING_COLUMNS, widths):
                rect = self._cell_text(row, ident, True).boundingRectWithSize_options_(
                    (width - 4, 1e7), NSStringDrawingUsesLineFragmentOrigin
                )
                height = max(height, rect.size.height + 4)
            self.wrapped_heights[key] = height
        return height

    @objc.python_method
    def _fit_width(self, ident: str):
        """Width that fits the longest value in a column, or None for columns that don't fit."""
        getters = {
            "time": lambda r: r.timestamp[11:23],
            "pid": lambda r: str(r.pid),
            "process": lambda r: r.process,
            "target": lambda r: r.target or "—",
            "code": lambda r: r.code,
            "script": lambda r: (r.script or r.reply_text) + ("" if r.kind == "event" else f"{r.kind}: "),
            "reply": lambda r: r.reply_text,
        }
        getter = getters.get(ident)
        if getter is None:
            return None
        # A single ⏎-flattened line is what an unwrapped cell shows, so measure that
        longest = max((len(getter(r).replace("\n", " ⏎ ")) for r in self.filtered[-5000:]), default=0)
        char_width = NSAttributedString.alloc().initWithString_attributes_("M", {NSFontAttributeName: _MONO}).size().width
        return min(10000.0, max(40.0, longest * char_width + 12))

    def tableView_sizeToFitWidthOfColumn_(self, table, column_index) -> float:
        """Double-clicking a column divider fits the column to its longest value."""
        column = table.tableColumns()[column_index]
        if table == self.sidebar_table:
            return column.width()
        fit = self._fit_width(column.identifier())
        return column.width() if fit is None else fit

    def toggleColumnWidth_(self, column_index) -> None:
        """Header double-click: fit the column to its content, or restore its default."""
        column = self.events_table.tableColumns()[column_index]
        default = DEFAULT_COLUMN_WIDTHS.get(column.identifier())
        fit = self._fit_width(column.identifier())
        if default is None or fit is None:
            return
        # Already fitted -> go back to default; otherwise expand to fit
        if abs(column.width() - fit) < 1.5 and abs(fit - default) > 1.5:
            column.setWidth_(default)
        else:
            column.setWidth_(fit)

    @objc.python_method
    def _cell_text(self, row: Row, ident: str, wrap: bool):
        """Highlighted text for the AppleScript or Reply cell of a row."""
        styled = _Attributed(None if wrap else _TRUNCATING)
        if ident == "script":
            body = row.script or row.reply_text
            if row.kind != "event":
                styled.add(f"{row.kind}: ", _MONO_BOLD, NSColor.systemOrangeColor())
        else:
            body = row.reply_text if row.kind != "reply" else ""
            if row.reply_error and body:
                prefix = f"error {row.reply_error}"
                styled.add(prefix, _MONO_BOLD, NSColor.systemRedColor())
                body = body[len(prefix):]
        # Clone sources are arbitrary captured output, not AppleScript, so leave them
        # unhighlighted; everything else gets syntax colors.
        emit = styled.add if row.kind == "clone" else styled.applescript
        if wrap:
            emit(body)
        else:
            # One line only: a leading badge flags multi-line content (stays visible even
            # when the tail is truncated), and breaks are marked inline.
            lines = body.count("\n") + 1
            if lines > 1:
                styled.add(f"⏎{lines} ", _MONO_BOLD, NSColor.systemTealColor())
            emit(body.replace("\n", " ⏎ "))
        return styled.text

    def tableView_isGroupRow_(self, table, index) -> bool:
        return table == self.sidebar_table and self.sidebar_entries[index][0] == "header"

    def tableView_shouldSelectRow_(self, table, index) -> bool:
        if table == self.sidebar_table:
            return self.sidebar_entries[index][0] == "item"
        return True

    def tableView_rowViewForRow_(self, table, index):
        if table != self.events_table:
            return None
        view = table.makeViewWithIdentifier_owner_("eventrow", self)
        if view is None:
            view = _EventRowView.alloc().init()
            view.setIdentifier_("eventrow")
        view._related = 0 <= index < len(self.filtered) and self.filtered[index].id in self.related_ids
        return view

    @objc.python_method
    def _update_related(self) -> None:
        row = self._selected_row()
        key = row.correlation if row is not None else None
        self.related_ids = {r.id for r in self.filtered if r.correlation == key} if key else set()

        def apply(view, index):
            if 0 <= index < len(self.filtered):
                rel = self.filtered[index].id in self.related_ids
                if getattr(view, "_related", False) != rel:
                    view._related = rel
                    view.setNeedsDisplay_(True)

        self.events_table.enumerateAvailableRowViewsUsingBlock_(apply)

    def tableViewSelectionDidChange_(self, notification) -> None:
        table = notification.object()
        if table == self.events_table:
            self._update_related()
            self._show_detail(self._selected_row())
            return
        if self.updating_sidebar:
            return
        include = {f: set() for f in FACETS}
        for i in _index_list(table.selectedRowIndexes()):
            if i >= len(self.sidebar_entries):
                break
            kind, facet, key, _n = self.sidebar_entries[i]
            if kind == "item":
                include[facet].add(key)
        self.filter.include = include
        self._refilter()

    @objc.python_method
    def _selected_row(self) -> Optional[Row]:
        index = self.events_table.selectedRow()
        return self.filtered[index] if 0 <= index < len(self.filtered) else None

    # -- context menus --------------------------------------------------------

    def menuNeedsUpdate_(self, menu) -> None:
        menu.removeAllItems()
        if menu == self.events_table.menu():
            index = self.events_table.clickedRow()
            if not 0 <= index < len(self.filtered):
                return
            row = self.filtered[index]
            self._menu_item(menu, "Copy JSON", "copyRowJSON:", row)
            menu.addItem_(NSMenuItem.separatorItem())
            for facet, label in (("process", "Process"), ("target", "Target"), ("code", "Event")):
                value = row.facet_value(facet)
                if value:
                    self._menu_item(menu, f"Mute {label} “{value}”", "muteFromMenu:", (facet, value))
        elif menu == self.sidebar_table.menu():
            index = self.sidebar_table.clickedRow()
            if not 0 <= index < len(self.sidebar_entries):
                return
            kind, facet, key, _n = self.sidebar_entries[index]
            if kind == "item" and facet != "indicator":
                self._menu_item(menu, f"Mute “{key}”", "muteFromMenu:", (facet, key))
            elif kind == "muted":
                self._menu_item(menu, f"Unmute “{key}”", "unmuteFromMenu:", (facet, key))

    @objc.python_method
    def _menu_item(self, menu, title, action, payload) -> None:
        mi = menu.addItemWithTitle_action_keyEquivalent_(title, action, "")
        mi.setTarget_(self)
        mi.setRepresentedObject_(json.dumps(payload) if isinstance(payload, tuple) else payload.id)

    @objc.IBAction
    def muteFromMenu_(self, sender) -> None:
        facet, value = json.loads(sender.representedObject())
        self._mute(facet, value)

    @objc.IBAction
    def unmuteFromMenu_(self, sender) -> None:
        facet, value = json.loads(sender.representedObject())
        self._unmute(facet, value)

    @objc.IBAction
    def copyRowJSON_(self, sender) -> None:
        row_id = sender.representedObject()
        row = next((r for r in self.filtered if r.id == row_id), None)
        if row is not None:
            self._copy_row(row)

    @objc.IBAction
    def copy_(self, _sender) -> None:
        # Reached only when no text view has focus: copy the selected event
        row = self._selected_row()
        if row is not None:
            self._copy_row(row)

    @objc.python_method
    def _copy_row(self, row: Row) -> None:
        from AppKit import NSPasteboard, NSPasteboardTypeString

        pb = NSPasteboard.generalPasteboard()
        pb.clearContents()
        pb.setString_forType_("\n".join(json.dumps(r) for r in row.records()), NSPasteboardTypeString)

    # -- detail pane ----------------------------------------------------------

    @objc.python_method
    def _show_detail(self, row: Optional[Row]) -> None:
        views = self.detail_views
        if row is None:
            hint = _Attributed().add("Select an event to see its details.", color=NSColor.secondaryLabelColor())
            for text in views.values():
                text.textStorage().setAttributedString_(hint.text)
            return

        base = row.base
        ev, rp = row.event_part, row.reply_part
        overview = _Attributed()
        overview.add(f"{row.process} → {row.target or 'self'}   {row.code}\n", _MONO_BOLD)
        for f in row.flags:
            overview.add("● ", color=_severity_color(f.severity)).add(
                f"{f.label}" + (f"  ({f.tactic})" if f.tactic else "") + "\n"
            )
        latency = ""
        if row.request is not None and row.reply is not None and row.request is not row.reply:
            latency = _latency(row.request.get("timestamp"), row.reply.get("timestamp"))
        meta = [
            ("Timestamp", row.timestamp),
            ("Process", f"{row.process_path} (pid {row.pid})"),
            ("Return ID", (ev or rp or {}).get("return_id")),
            ("Thread", base.get("threadID")),
            ("User ID", base.get("userID")),
            ("Reply", ("error " + row.reply_error) if row.reply_error else ("ok" if rp else "—")),
            ("Reply after", latency or "—"),
        ]
        overview.add("\n")
        for key, value in meta:
            overview.add(f"{key:<12}", color=NSColor.secondaryLabelColor()).add(f"{'' if value is None else value}\n")
        overview.add("\n")
        if row.kind == "clone":
            # Clone sources are arbitrary captured output, not AppleScript
            overview.section("clone", row.script, highlight=False)
        overview.section("event", ev and ev.get("applescript"), highlight=True)
        overview.section("reply", rp and rp.get("applescript"), highlight=True)
        views["overview"].textStorage().setAttributedString_(overview.text)

        raw = _Attributed()
        raw.section("event", ev and ev.get("raw")).section("reply", rp and rp.get("raw"))
        for r in row.records():
            raw.section("eventMessage", (r.get("eventMessage") or "").strip())
        views["raw"].textStorage().setAttributedString_(raw.text)

        js = "\n\n".join(json.dumps(r, indent=2) for r in row.records())
        views["json"].textStorage().setAttributedString_(_Attributed().add(js).text)

    # -- files ----------------------------------------------------------------

    @objc.IBAction
    def openDocument_(self, _sender) -> None:
        panel = NSOpenPanel.openPanel()
        panel.setAllowedFileTypes_(["logarchive", "ndjson", "jsonl"])
        panel.setTreatsFilePackagesAsDirectories_(False)
        if panel.runModal() != NSModalResponseOK:
            return
        path = panel.URL().path()
        if self.store.rows and not self._confirm(
            "Replace the current events?",
            f"Opening {os.path.basename(path)} stops monitoring and replaces the "
            f"{len(self.store.rows):,} events in the table. Export them first to keep them.",
            "Open",
        ):
            return
        self.monitor.stop()
        self._clear()
        try:
            self.monitor.start(path)
        except Exception as e:  # e.g. log show failing to start
            self._alert("Could not open file", str(e))
        self.window.setTitle_(f"AEMonitor — {os.path.basename(path)}")
        self._update_toggle()
        self._update_status()

    @objc.IBAction
    def exportEvents_(self, _sender) -> None:
        panel = NSSavePanel.savePanel()
        panel.setAllowedFileTypes_(["ndjson"])
        panel.setNameFieldStringValue_(f"aemonitor-{datetime.now():%Y%m%d-%H%M%S}.ndjson")
        if panel.runModal() != NSModalResponseOK:
            return
        seen = set()
        with open(panel.URL().path(), "w", encoding="utf-8") as f:
            for row in self.filtered:
                for record in row.records():
                    if id(record) not in seen:
                        seen.add(id(record))
                        f.write(json.dumps(record) + "\n")

    @objc.IBAction
    def showLog_(self, _sender) -> None:
        NSWorkspace.sharedWorkspace().openFile_(LOG_PATH)

    # -- helpers --------------------------------------------------------------

    @objc.python_method
    def _alert(self, title: str, message: str) -> None:
        alert = NSAlert.alloc().init()
        alert.setMessageText_(title)
        alert.setInformativeText_(message)
        alert.runModal()

    @objc.python_method
    def _confirm(self, title: str, message: str, button: str) -> bool:
        alert = NSAlert.alloc().init()
        alert.setMessageText_(title)
        alert.setInformativeText_(message)
        alert.addButtonWithTitle_(button)
        alert.addButtonWithTitle_("Cancel")
        return alert.runModal() == NSAlertFirstButtonReturn


def _latency(a: Optional[str], b: Optional[str]) -> str:
    fmt = "%Y-%m-%d %H:%M:%S.%f%z"
    try:
        delta = datetime.strptime(b or "", fmt) - datetime.strptime(a or "", fmt)
    except ValueError:
        return ""
    return f"{delta.total_seconds() * 1000:.0f} ms"


def _redirect_output() -> None:
    """Finder-launched apps have no terminal; keep warnings in a log file instead."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    log = open(LOG_PATH, "a", buffering=1, encoding="utf-8")
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)
    sys.stdout = sys.stderr = log


def main() -> int:
    if not sys.stderr or not sys.stderr.isatty():
        _redirect_output()
    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
