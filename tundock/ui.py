"""Native GTK desktop interface."""

from collections import deque
from dataclasses import dataclass, field
import os
from pathlib import Path
from queue import Empty, SimpleQueue
import re
import shlex
import signal
import subprocess
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("GdkPixbuf", "2.0")
gi.require_version("Adw", "1")
from gi.repository import GLib

APP_ID = "io.github.tundock.Tundock"
# GDK reads the program name when importing GTK initializes the display.
GLib.set_prgname(APP_ID)

from gi.repository import Adw, Gdk, GdkPixbuf, Gio, Gtk, Pango

from . import __version__, storage
from .core import (
    ROOT, POLICIES, RESOLVERS, Options, Proxy, Report, Tunnel, TunnelError,
    app_command, dependency_paths, network_modes,
)
from .diagnostics import probe
from .launchcheck import flatpak_target, launch_target

PROBE_HINT = "The test contacts Cloudflare and the selected encrypted DNS resolver through the proxy."


def label(title, *styles, wrap=False):
    widget = Gtk.Label(label=title, xalign=0, wrap=wrap)
    for style in styles:
        widget.add_css_class(style)
    return widget


def box(*children, vertical=False, spacing=0):
    widget = Gtk.Box(orientation=Gtk.Orientation.VERTICAL if vertical else Gtk.Orientation.HORIZONTAL,
                     spacing=spacing)
    for child in children:
        widget.append(child)
    return widget


def button(title, action, *styles, icon=None):
    if icon:
        widget = Gtk.Button(child=Adw.ButtonContent(icon_name=icon, label=title))
    else:
        widget = Gtk.Button(label=title)
    for style in styles:
        widget.add_css_class(style)
    widget.connect("clicked", action)
    return widget


def entry(placeholder, *, secret=False):
    widget = Gtk.PasswordEntry(show_peek_icon=True) if secret else Gtk.Entry()
    widget.set_property("placeholder-text", placeholder)
    widget.set_hexpand(True)
    return widget


def clear_list(widget):
    while child := widget.get_first_child():
        widget.remove(child)


def desktop_command(info):
    if info.get_boolean("Terminal"):
        raise TunnelError("This entry needs a terminal. Choose a graphical application or an executable that opens its own window.")
    raw = info.get_string("Exec") or info.get_commandline()
    if not raw:
        raise TunnelError("This application does not provide an executable command.")
    result = []
    for arg in shlex.split(raw):
        if arg == "%i":
            icon = info.get_string("Icon")
            if icon:
                result.extend(("--icon", icon))
            continue
        replacements = {"%": "%", "c": info.get_name(), "k": info.get_filename() or ""}
        value = re.sub(r"%([%a-zA-Z])", lambda m: replacements.get(m[1], ""), arg)
        if value:
            result.append(value)
    if not result:
        raise TunnelError("This application does not provide an executable command.")
    return shlex.join(result)


class SessionLog:
    """Keep a bounded record of worker output and render it in short batches."""

    max_lines = 500
    max_columns = 2048

    def __init__(self, *, enabled=True):
        self._enabled = enabled
        self.buffer = Gtk.TextBuffer()
        self.view = Gtk.TextView(
            buffer=self.buffer, editable=False, cursor_visible=False,
            monospace=True, wrap_mode=Gtk.WrapMode.CHAR,
            left_margin=10, right_margin=10, top_margin=8, bottom_margin=8,
        )
        self.scroll = Gtk.ScrolledWindow(
            child=self.view, min_content_height=160, hscrollbar_policy=Gtk.PolicyType.NEVER,
        )
        self.scroll.add_css_class("session-log")
        self.end = self.buffer.create_mark(None, self.buffer.get_end_iter(), False)
        self.pending = deque(maxlen=self.max_lines)
        self.lock = threading.Lock()
        self.flush_source = 0

    def is_enabled(self):
        with self.lock:
            return self._enabled

    def set_enabled(self, enabled):
        with self.lock:
            self._enabled = enabled
            if not enabled:
                self.pending.clear()
                if self.flush_source:
                    GLib.source_remove(self.flush_source)
                    self.flush_source = 0

    def append(self, source, line):
        with self.lock:
            if not self._enabled:
                return
            text = f"[{source}] {line.rstrip()}".replace("\r", " ").replace("\n", " ").replace("\0", "�")
            if len(text) > self.max_columns:
                text = text[:self.max_columns - 1] + "…"
            self.pending.append(text)
            if not self.flush_source:
                self.flush_source = GLib.timeout_add(75, self.flush)

    def flush(self, *, immediate=False):
        with self.lock:
            if immediate and self.flush_source:
                GLib.source_remove(self.flush_source)
            self.flush_source = 0
            if not self.pending:
                return GLib.SOURCE_REMOVE
            text = "\n".join(self.pending) + "\n"
            self.pending.clear()
        adjustment = self.scroll.get_vadjustment()
        follow = adjustment.get_upper() - adjustment.get_page_size() - adjustment.get_value() < 12
        self.buffer.insert(self.buffer.get_end_iter(), text)
        excess = self.buffer.get_line_count() - self.max_lines - 1
        if excess > 0:
            _, cutoff = self.buffer.get_iter_at_line(excess)
            self.buffer.delete(self.buffer.get_start_iter(), cutoff)
        if follow:
            self.show_latest()
        return GLib.SOURCE_REMOVE

    def show_latest(self):
        self.view.scroll_to_mark(self.end, 0.0, True, 0.0, 1.0)


@dataclass
class Session:
    row: Adw.ExpanderRow
    stop: threading.Event
    button: Gtk.Button
    log: SessionLog
    log_label: Gtk.Label
    check_button: Gtk.Button
    network: Gtk.Label
    tunnel: Tunnel | None = None
    process: subprocess.Popen | None = None
    check_stop: threading.Event | None = None


@dataclass
class Service:
    proxy: Proxy | None
    options: Options
    udp: bool
    ipv6: bool
    direct: bool
    log: SessionLog
    stop: threading.Event = field(default_factory=threading.Event)
    commands: SimpleQueue = field(default_factory=SimpleQueue)
    tunnel: Tunnel | None = None
    active: bool = False
    pending: str | None = "start"
    selecting_direct: bool | None = None

    @property
    def ready(self):
        return (self.active and self.pending is None and self.selecting_direct is None
                and not self.stop.is_set())

    @property
    def route(self):
        return "Direct" if self.direct else self.proxy.address

    @property
    def detail(self):
        udp = self.options.udp != "Block" if self.direct else self.udp
        return f"{self.route} · UDP {'on' if udp else 'blocked'} · IPv6 {'on' if self.ipv6 else 'blocked'}"


@dataclass
class ProgramEntry:
    args: list[str]
    directory: Path
    name: str
    terminal: bool
    row: Adw.ActionRow
    play: Gtk.Button
    view_log: Gtk.Button
    detail: str
    session_id: int | None = None
    last_log: Adw.ExpanderRow | None = None


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Tundock", default_width=1090, default_height=795)
        self.set_size_request(760, 560)
        self.add_css_class("tundock")
        self.report = None
        self.report_key = None
        self.test_stop = None
        self.closing = False
        self.sessions = {}
        self.next_session = 0
        self.programs = []
        self.session_programs = {}
        self.service = None
        self._syncing_route = False
        self.selected_preset = None
        self.preset_error = None
        try:
            self.presets = storage.load()
        except (OSError, ValueError, KeyError, TypeError, TunnelError):
            self.presets = []
            self.preset_error = "Saved presets could not be read. Check the preset file before saving again."
        self.bookmark_error = None
        try:
            self.bookmarks = storage.load_bookmarks()
        except (OSError, ValueError, KeyError, TypeError, TunnelError):
            self.bookmarks = []
            self.bookmark_error = "Saved proxies could not be read. Check the saved proxy file before making changes."
        self.connect("close-request", self._close_requested)

        self.overlay = Adw.ToastOverlay()
        self.set_content(self.overlay)
        header = Adw.HeaderBar()
        header.add_css_class("topbar")
        menu = Gio.Menu()
        menu.append("Enable Logging", "app.session-logging")
        menu.append("Requirements", "app.requirements")
        menu.append("About Tundock", "app.about")
        menu.append("Quit Tundock", "app.quit")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                       tooltip_text="Tundock menu"))
        brand_icon = self._brand_picture(24)
        header.set_title_widget(box(brand_icon, label("Tundock", "wordmark"), spacing=8))

        self.preset_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.preset_list.add_css_class("presets")
        profile_header = box(label("Presets", "sidebar-title"), spacing=8)
        profile_header.set_margin_bottom(4)
        self.preset_scroll = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        self.preset_scroll.set_child(self.preset_list)
        self.active_count = label("No active sessions", "sidebar-footnote", wrap=True)
        sidebar = box(profile_header, self.preset_scroll, self.active_count, vertical=True, spacing=12)
        sidebar.add_css_class("sidebar")
        sidebar.set_size_request(210, -1)
        self._render_presets()

        self.proxy = entry("socks5://127.0.0.1:8083")
        self.proxy.add_css_class("mono")
        self.username = entry("Username")
        self.password = entry("Password", secret=True)
        self.command = entry("Executable path or command with arguments")
        self.command.add_css_class("mono")
        self.folder = entry(str(Path.home()))
        self.resolver = Gtk.DropDown.new_from_strings(list(RESOLVERS))
        self.udp_policy = Gtk.DropDown.new_from_strings(list(POLICIES))
        self.ipv6_policy = Gtk.DropDown.new_from_strings(list(POLICIES))
        self.desktop = Gtk.Switch(valign=Gtk.Align.CENTER)
        self.test = button("Test connection", self._test, "test-button", icon="view-refresh-symbolic")

        heading = box(label("Isolated applications", "headline", wrap=True),
                      label("Run selected programs through a private network.", "subheading", wrap=True),
                      vertical=True, spacing=7)
        heading.set_hexpand(True)
        hero_icon = self._brand_picture(64)
        hero_icon.set_valign(Gtk.Align.CENTER)
        hero = box(heading, hero_icon, spacing=20)
        hero.add_css_class("hero")

        self.bookmark_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.bookmark_list.add_css_class("boxed-list")
        bookmarks_scroll = Gtk.ScrolledWindow(
            child=self.bookmark_list, min_content_width=270, max_content_height=260,
            propagate_natural_height=True, hscrollbar_policy=Gtk.PolicyType.NEVER,
        )
        self.bookmark_menu = Gtk.MenuButton(label="Saved proxies", popover=Gtk.Popover(child=bookmarks_scroll))
        self.bookmark_menu.add_css_class("small-button")
        self._render_bookmarks()

        proxy_title = label("Proxy", "section-title")
        proxy_title.set_hexpand(True)
        self.use_proxy = Gtk.Switch(active=True, valign=Gtk.Align.CENTER)
        self.use_proxy.set_tooltip_text("Switch the route for new connections in this private tunnel.")
        self.use_proxy.connect("notify::active", self._route_toggled)
        proxy_hint = label("SOCKS5 or HTTP(S) CONNECT · stop the session to change the address",
                           "field-hint", wrap=True)
        proxy_hint.set_hexpand(True)
        save_proxy = button("Save proxy", self._save_bookmark, "small-button", icon="bookmark-new-symbolic")
        proxy_card = box(box(proxy_title, label("Use upstream proxy"), self.use_proxy, self.test, spacing=10), self.proxy,
                         box(proxy_hint, self.bookmark_menu, save_proxy, spacing=8),
                         vertical=True, spacing=9)
        proxy_card.add_css_class("card")

        self.metrics = {}
        metrics = Gtk.Grid(column_spacing=8, row_spacing=8, column_homogeneous=True)
        for index, (key, name) in enumerate(
            (("tun", "Private TUN"), ("tcp", "HTTPS"), ("dns", "Encrypted DNS"), ("udp", "UDP"), ("ipv6", "IPv6"))
        ):
            state = label("Not tested", "metric-state")
            state.set_ellipsize(Pango.EllipsizeMode.END)
            tile = box(label(name, "metric-label"), state, vertical=True, spacing=5)
            tile.add_css_class("metric")
            metrics.attach(tile, index, 0, 1, 1)
            self.metrics[key] = (tile, state)
        self.probe_detail = label(PROBE_HINT, "field-hint", wrap=True)
        self.probe_detail.set_selectable(True)
        self.protocol_plan = label("", "protocol-plan", wrap=True)
        self.protocol_plan.set_visible(False)
        dependency_text = label("", "field-hint", wrap=True)
        dependency_text.set_hexpand(True)
        dependency_notice = box(
            dependency_text,
            button("Requirements", lambda *_: app.activate_action("requirements", None)),
            spacing=12,
        )
        dependency_notice.add_css_class("dependency-notice")
        dependency_notice.set_visible(False)
        try:
            dependency_paths()
        except TunnelError as error:
            dependency_text.set_text(str(error))
            dependency_notice.set_visible(True)

        browse = button("Browse", self._browse, "small-button")
        pick = button("Installed apps", self._choose_application, "small-button")
        commands = button("Add Command", self._command_dialog, "small-button")
        add = button("Add to list", self._queue_from_form, "small-button")
        self.program_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.program_list.add_css_class("boxed-list")
        self.program_list.set_visible(False)
        app_card = box(label("Programs", "section-title"), self.command, box(pick, browse, commands, add, spacing=8),
                       vertical=True, spacing=9)
        app_card.append(self.program_list)
        app_card.append(label("Start the session, then select Run. Stop Session pauses networking and keeps programs open.",
                              "field-hint", wrap=True))
        app_card.add_css_class("card")

        advanced = Adw.ExpanderRow(title="Connection options", subtitle="Credentials, DNS and desktop integration")
        for title, subtitle, controls in (
            ("Proxy sign-in", "Optional. Credentials stay in memory for this session.", [self.username, self.password]),
            ("Working folder", "Defaults to your home folder.", [self.folder]),
            ("Encrypted DNS", "Resolved through the proxy using HTTPS.", [self.resolver]),
            ("UDP traffic", "Automatic enables UDP only after a successful UDP probe.", [self.udp_policy]),
            ("IPv6 traffic", "Automatic enables IPv6 only after verified HTTPS over IPv6.", [self.ipv6_policy]),
            ("Share desktop services", "Enable for desktop sign-in or portals. Host services run outside the tunnel.",
             [self.desktop]),
        ):
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            for widget in controls:
                widget.set_valign(Gtk.Align.CENTER)
                if isinstance(widget, (Gtk.Entry, Gtk.PasswordEntry)):
                    widget.set_property("width-chars", 12)
                row.add_suffix(widget)
            advanced.add_row(row)
        advanced_group = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        advanced_group.add_css_class("boxed-list")
        advanced_group.append(advanced)

        save = button("Save preset", self._save_preset, icon="bookmark-new-symbolic")
        self.service_status = label("Network stopped", "field-hint", wrap=True)
        self.launch_button = button("Start Session", self._toggle_service, "launch-button",
                                    icon="media-playback-start-symbolic")
        self.latest_session_button = button(
            "Latest log", self._view_latest_session, icon="utilities-terminal-symbolic",
        )
        self.latest_session_button.set_visible(False)
        actions = box(self.latest_session_button, self.service_status, Gtk.Box(hexpand=True), save,
                      self.launch_button, spacing=9)
        footer = Adw.Clamp(maximum_size=965, tightening_threshold=785, child=actions)
        footer.add_css_class("action-bar")

        self.session_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.session_list.add_css_class("boxed-list")
        self.empty_session = label("Run a program to see its session log.", "field-hint", wrap=True)
        self.service_log_row = Adw.ExpanderRow(title="Service log", subtitle="Tunnel startup and route changes")
        self.service_log_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.service_log_list.add_css_class("boxed-list")
        self.service_log_list.append(self.service_log_row)
        self.service_log_list.set_visible(False)
        self.service_log_view = None
        sessions = box(label("Sessions", "section-title"), self.empty_session, self.service_log_list,
                       self.session_list, vertical=True, spacing=9)

        content = box(dependency_notice, hero, proxy_card, metrics, self.probe_detail, self.protocol_plan,
                      app_card, advanced_group,
                      sessions, vertical=True, spacing=14)
        content.add_css_class("content")
        clamp = Adw.Clamp(maximum_size=965, tightening_threshold=785, child=content)
        self.main_scroll = Gtk.ScrolledWindow(
            hscrollbar_policy=Gtk.PolicyType.NEVER, hexpand=True, vexpand=True, child=clamp,
        )
        right = box(self.main_scroll, footer, vertical=True)
        right.set_hexpand(True)
        main = box(sidebar, right)
        main.add_css_class("workspace")
        main.set_vexpand(True)
        self.overlay.set_child(box(header, main, vertical=True))
        for widget in (self.proxy, self.username, self.password):
            widget.connect("changed", self._settings_changed)
        for widget in (self.resolver, self.udp_policy, self.ipv6_policy):
            widget.connect("notify::selected", self._settings_changed)
        self.desktop.connect("notify::active", self._settings_changed)
        if self.preset_error:
            GLib.idle_add(self._toast, self.preset_error)

    @staticmethod
    def _brand_picture(size):
        pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(ROOT / "tundock.png"), size, size, True)
        return Gtk.Image.new_from_paintable(Gdk.Texture.new_for_pixbuf(pixbuf))

    def _toast(self, message):
        self.overlay.add_toast(Adw.Toast(title=str(message)))
        return False

    def _options(self):
        return Options(tuple(RESOLVERS)[self.resolver.get_selected()], POLICIES[self.udp_policy.get_selected()],
                       POLICIES[self.ipv6_policy.get_selected()], self.desktop.get_active())

    def _configuration(self):
        proxy = Proxy.parse(self.proxy.get_text(), self.username.get_text(), self.password.get_text())
        return proxy, self._options()

    def _input(self):
        proxy, options = self._configuration()
        if self.proxy.get_text() != proxy.address:
            self.proxy.set_text(proxy.address)
            self.username.set_text(proxy.username)
            self.password.set_text(proxy.password)
        return proxy, options

    def _render_bookmarks(self):
        clear_list(self.bookmark_list)
        if not self.bookmarks:
            title = "Saved proxies unavailable" if self.bookmark_error else "No saved proxies"
            self.bookmark_list.append(Adw.ActionRow(title=title))
        for bookmark in self.bookmarks:
            row = Adw.ActionRow(title=GLib.markup_escape_text(bookmark.name),
                                subtitle=GLib.markup_escape_text(bookmark.address), activatable=True)
            row.set_title_lines(1)
            row.set_subtitle_lines(1)
            remove = Gtk.Button.new_from_icon_name("edit-delete-symbolic")
            remove.add_css_class("flat")
            remove.set_valign(Gtk.Align.CENTER)
            remove.set_tooltip_text(f"Delete {bookmark.name} proxy bookmark")
            remove.connect("clicked", lambda _, item=bookmark: self._remove_bookmark(item))
            row.add_suffix(remove)
            row.connect("activated", self._apply_bookmark, bookmark)
            self.bookmark_list.append(row)

    def _apply_bookmark(self, _, bookmark):
        self.username.set_text("")
        self.password.set_text("")
        self.proxy.set_text(bookmark.address)
        self.bookmark_menu.popdown()

    def _save_bookmark(self, *_):
        if self.bookmark_error:
            self._toast(self.bookmark_error)
            return
        try:
            proxy = Proxy.parse(self.proxy.get_text())
        except TunnelError as error:
            self._toast(error)
            return
        dialog = Adw.MessageDialog(
            transient_for=self, heading="Save proxy",
            body=f"{proxy.address}\nOnly the address is saved.",
        )
        name = Gtk.Entry(text=proxy.host, max_length=60, activates_default=True)
        dialog.set_extra_child(name)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.set_close_response("cancel")

        def save_response(_, response):
            if response != "save":
                return
            title = name.get_text().strip()
            if not title:
                self._toast("Enter a name for the proxy.")
                return
            if any(item.name.casefold() == title.casefold() for item in self.bookmarks):
                self._toast("A saved proxy has that name. Choose a different name.")
                return
            bookmark = storage.ProxyBookmark(title, proxy.address)
            updated = sorted([*self.bookmarks, bookmark], key=lambda item: item.name.casefold())
            if self._store_bookmarks(updated):
                self._toast("Proxy saved.")

        dialog.connect("response", save_response)
        dialog.present()

    def _remove_bookmark(self, bookmark):
        if self._store_bookmarks([item for item in self.bookmarks if item != bookmark]):
            self._toast("Proxy bookmark deleted.")

    def _store_bookmarks(self, bookmarks):
        try:
            storage.save_bookmarks(bookmarks)
        except OSError as error:
            self._toast(f"Couldn't save proxy bookmarks. {error.strerror}")
            return False
        self.bookmarks = bookmarks
        self._render_bookmarks()
        return True

    def _update_report(self, report):
        details = []
        for name, (tile, state) in self.metrics.items():
            metric = getattr(report, name)
            state.set_text(metric.state)
            for old in ("verified", "limited"):
                tile.remove_css_class(old)
            if metric.verified:
                tile.add_css_class("verified")
            elif metric.state in ("Unavailable", "Unverified", "Blocked"):
                tile.add_css_class("limited")
            tile.set_tooltip_text(metric.detail or None)
            if metric.detail:
                details.append(metric.detail)
        self.probe_detail.set_text("\n".join(details) if details else PROBE_HINT)
        self._update_protocol_plan(report)

    def _update_protocol_plan(self, report):
        if self.service is not None and (self.service.active or self.service.pending):
            self.protocol_plan.set_text(
                f"Service route · {self.service.detail} · Proxy address changes apply after restarting."
            )
            self.protocol_plan.set_visible(True)
            return
        if not self.use_proxy.get_active():
            self.protocol_plan.set_text("Next start · Direct")
            self.protocol_plan.set_visible(True)
            return
        try:
            proxy, options = self._configuration()
        except TunnelError:
            self.protocol_plan.set_visible(False)
            return
        udp, ipv6 = network_modes(proxy, options, report)
        modes = []
        for name, policy, enabled, result in (
            ("UDP", options.udp, udp, report.udp), ("IPv6", options.ipv6, ipv6, report.ipv6),
        ):
            if name == "UDP" and proxy.scheme != "socks5":
                mode = "off (CONNECT uses TCP)"
            elif enabled:
                mode = "on (verified)" if result.verified else "on (manual)"
            elif policy == "Automatic":
                mode = "off (unverified)"
            else:
                mode = "off (manual)"
            modes.append(f"{name} {mode}")
        self.protocol_plan.set_text("Next start · " + " · ".join(modes))
        self.protocol_plan.set_visible(True)

    def _settings_changed(self, *_):
        self.report = self.report_key = None
        self._update_report(Report())
        if self.test_stop:
            self._cancel_test()

    def _cancel_test(self):
        if self.test_stop:
            self.test_stop.set()
            self.test.set_sensitive(False)
            self.test.get_child().set_label("Cancelling…")
            self.probe_detail.set_text("Closing the temporary test network…")

    def _test(self, *_):
        if self.closing:
            return
        if self.test_stop:
            self._cancel_test()
            return
        try:
            key = self._input()
            dependency_paths()
        except TunnelError as error:
            self._toast(error)
            return
        stop = threading.Event()
        self.test_stop = stop
        self.report = self.report_key = None
        self._update_report(Report())
        self.test.get_child().set_label("Cancel test")
        self.test.get_child().set_icon_name("process-stop-symbolic")
        self.probe_detail.set_text("Testing the proxy inside a temporary private network…")

        def run():
            try:
                result = probe(*key, stop=stop)
                GLib.idle_add(self._test_finished, stop, key, result, None)
            except InterruptedError:
                GLib.idle_add(self._test_finished, stop, key, None, None)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                GLib.idle_add(self._test_finished, stop, key, None, str(error))

        threading.Thread(target=run, daemon=True).start()

    def _test_finished(self, stop, key, result, error):
        if self.test_stop is not stop:
            return False
        self.test_stop = None
        if self.closing:
            self._complete_close()
            return False
        self.test.set_sensitive(True)
        self.test.get_child().set_label("Test connection")
        self.test.get_child().set_icon_name("view-refresh-symbolic")
        try:
            current = self._configuration()
        except TunnelError:
            current = None
        if current != key:
            self._update_report(Report())
            return False
        if stop.is_set():
            self.probe_detail.set_text("Connection test cancelled.")
        elif error:
            self.probe_detail.set_text(error)
            self._toast("Connection test couldn't finish.")
        elif result is not None:
            self.report_key, self.report = key, result
            self._update_report(result)
        return False

    def _toggle_service(self, *_):
        service = self.service
        if self.closing or (service is not None and (service.pending or service.selecting_direct is not None)):
            return
        if service is not None and service.active:
            self._stop_service()
            return
        try:
            direct = not self.use_proxy.get_active()
            if self.proxy.get_text().strip() or not direct:
                proxy, options = self._input()
            else:
                proxy, options = None, self._options()
            dependency_paths()
        except (TunnelError, OSError) as error:
            self._toast(error)
            return
        report = self.report if self.report_key == (proxy, options) else Report()
        udp, ipv6 = network_modes(proxy, options, report)
        if service is None:
            log = SessionLog(enabled=self.get_application().session_logging_enabled())
            service = Service(proxy, options, udp, ipv6, direct, log)
            self.service = service
            if self.service_log_view is not None:
                self.service_log_row.remove(self.service_log_view)
            self.service_log_view = log.scroll
            self.service_log_row.add_row(log.scroll)
            self.service_log_row.set_expanded(False)
            self.service_log_list.set_visible(True)
            threading.Thread(target=self._run_service, args=(service,), name="tundock-network",
                             daemon=True).start()
        service.proxy, service.options, service.udp, service.ipv6, service.direct = proxy, options, udp, ipv6, direct
        service.pending = "start"
        service.log.append("Tundock", f"Starting private network · {service.route}")
        service.commands.put(("start", (proxy, options, udp, ipv6, direct)))
        self._refresh_service()

    def _run_service(self, service):
        error = None
        try:
            with Tunnel(
                service.proxy, service.options, udp=service.udp, ipv6=service.ipv6, switchable=True,
                initial_direct=service.direct, output=service.log.append, capture_enabled=service.log.is_enabled,
            ) as tunnel:
                active = False
                while not service.stop.is_set():
                    try:
                        operation, settings = service.commands.get(timeout=0.2)
                    except Empty:
                        if not active or (tunnel.engine is not None and tunnel.engine.poll() is None):
                            continue
                        operation, settings = "lost", None
                    if service.stop.is_set():
                        break
                    problem = "The private tunnel engine exited." if operation == "lost" else None
                    try:
                        if operation == "start":
                            proxy, options, udp, ipv6, direct = settings
                            tunnel.configure(proxy, options, udp=udp, ipv6=ipv6, initial_direct=direct,
                                             output=service.log.append, capture_enabled=service.log.is_enabled)
                            tunnel.start(service.stop)
                        else:
                            tunnel.stop_network()
                    except InterruptedError:
                        if service.stop.is_set():
                            break
                        problem = "The private network operation was interrupted."
                    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                        problem = str(failure)
                    active = tunnel.engine is not None and tunnel.engine.poll() is None
                    GLib.idle_add(self._service_result, service, tunnel, operation, active, problem)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
            error = str(failure)
        finally:
            service.stop.set()
            GLib.idle_add(self._service_finished, service, error)

    def _service_result(self, service, tunnel, operation, active, error):
        if self.service is not service or service.stop.is_set():
            return GLib.SOURCE_REMOVE
        service.tunnel = tunnel
        service.active = active
        if operation == service.pending:
            service.pending = None
        if error:
            service.log.append("Network", error)
            self._toast(error)
            self.service_log_row.set_expanded(True)
        if service.pending is None:
            if active:
                detail = f"Private network ready · {service.route}"
            else:
                detail = "Private network stopped. Running programs are offline."
                self._cancel_exit_checks()
            service.log.append("Network", detail)
            self._refresh_running_programs(service, detail)
        self._refresh_service()
        return GLib.SOURCE_REMOVE

    def _service_finished(self, service, error):
        if self.service is not service:
            return GLib.SOURCE_REMOVE
        self.service = None
        for session_id in self.sessions:
            self._stop_session(session_id)
        service.log.append("Tundock", "Private tunnel closed.")
        service.log.flush(immediate=True)
        service.log.set_enabled(False)
        if error and not self.closing:
            self._toast(error)
            self.service_log_row.set_expanded(True)
        self._refresh_service()
        self._complete_close()
        return GLib.SOURCE_REMOVE

    def _stop_service(self):
        service = self.service
        if service is None or service.stop.is_set() or service.pending == "stop" or not (service.active or service.pending):
            return
        service.pending = "stop"
        self._cancel_exit_checks()
        service.commands.put(("stop", None))
        self._refresh_service()

    def _set_proxy_switch(self, active):
        self._syncing_route = True
        self.use_proxy.set_active(active)
        self._syncing_route = False

    def _route_toggled(self, *_):
        if self._syncing_route:
            return
        service = self.service
        if service is None or (not service.active and service.pending is None):
            self._update_protocol_plan(self.report or Report())
            return
        direct = not self.use_proxy.get_active()
        if not service.ready:
            self._set_proxy_switch(not service.direct)
            return
        if direct == service.direct:
            return
        if not direct and service.proxy is None:
            self._set_proxy_switch(not service.direct)
            self._toast("Enter an upstream and restart the service to enable proxy routing.")
            return
        service.selecting_direct = direct
        self._refresh_service()

        def run():
            error = None
            try:
                service.tunnel.set_direct(direct)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
                error = str(failure)
            GLib.idle_add(self._route_selected, service, direct, error)

        threading.Thread(target=run, name="tundock-route", daemon=True).start()

    def _route_selected(self, service, direct, error):
        if self.service is not service or service.stop.is_set():
            return GLib.SOURCE_REMOVE
        service.selecting_direct = None
        if error:
            service.log.append("Network", error)
            self._set_proxy_switch(not service.direct)
            self._toast(error)
        else:
            service.direct = direct
            self._set_proxy_switch(not direct)
            message = f"Active route changed to {service.route}."
            service.log.append("Network", message)
            if service.pending is None:
                self._refresh_running_programs(service, message)
        self._refresh_service()
        return GLib.SOURCE_REMOVE

    def _refresh_running_programs(self, service, message):
        for session in self.sessions.values():
            if session.process is not None and not session.stop.is_set():
                session.log.append("Network", message)
                self._update_program_network(session, service)

    @staticmethod
    def _update_program_network(session, service):
        if service.active:
            session.row.set_subtitle(GLib.markup_escape_text(f"Running · {service.detail}"))
            session.network.set_text("Check the exit IP for this route.")
        else:
            session.row.set_subtitle("Running · Network offline")
            session.network.set_text("Start Session to reconnect this program.")

    def _refresh_service(self):
        state = self.launch_button.get_child()
        service = self.service
        active = bool(service and service.active)
        pending = service.pending if service is not None else None
        selecting = service is not None and service.selecting_direct is not None
        if active:
            self.launch_button.add_css_class("active-session")
        else:
            self.launch_button.remove_css_class("active-session")
        if self.closing or pending == "stop":
            state.set_label("Stopping…")
            state.set_icon_name("process-stop-symbolic")
            self.service_status.set_text("Stopping private network…")
        elif pending == "start":
            state.set_label("Starting…")
            state.set_icon_name("media-playback-start-symbolic")
            self.service_status.set_text("Starting private network…")
        elif active:
            state.set_label("Stop Session")
            state.set_icon_name("process-stop-symbolic")
            self.service_status.set_text("Switching route…" if selecting else f"Running · {service.route}")
        else:
            state.set_label("Start Session")
            state.set_icon_name("media-playback-start-symbolic")
            self.service_status.set_text("Network stopped · programs offline" if self.sessions else "Network stopped")
        self.launch_button.set_sensitive(not (self.closing or pending or selecting))
        ready = bool(service and service.ready and not self.closing)
        editable = not (active or pending or self.closing)
        self.use_proxy.set_sensitive(editable or (ready and not any(
            session.check_stop is not None for session in self.sessions.values()
        )))
        for widget in (self.proxy, self.username, self.password, self.bookmark_menu):
            widget.set_sensitive(editable)
        for session in self.sessions.values():
            session.check_button.set_sensitive(bool(ready and session.process is not None and session.check_stop is None
                                                     and not session.stop.is_set()))
        self._update_protocol_plan(self.report if self.report is not None else Report())
        for item in self.programs:
            running = self.sessions.get(item.session_id)
            content = item.play.get_child()
            content.set_label("Stop" if running else "Run")
            content.set_icon_name("process-stop-symbolic" if running else "media-playback-start-symbolic")
            item.play.set_tooltip_text(f"{'Stop' if running else 'Run'} {item.name}")
            item.play.set_sensitive(not running.stop.is_set() if running else ready)
            detail = running.row.get_subtitle() if running else GLib.markup_escape_text(item.detail)
            item.row.set_subtitle(detail)
            item.view_log.set_sensitive(item.last_log is not None)

    def _queue_from_form(self, *_, display_name=None):
        try:
            args, directory = app_command(self.command.get_text(), self.folder.get_text())
            flatpak = flatpak_target(args)
        except (TunnelError, OSError, ValueError) as error:
            self._toast(error)
            return None
        target = launch_target(args) or args
        name = display_name or (flatpak[1] if flatpak else Path(target[0]).name)
        return self._queue_program(args, directory, name)

    def _queue_program(self, args, directory, name, *, terminal=False):
        existing = next((item for item in self.programs
                         if item.args == args and item.directory == directory), None)
        if existing:
            return existing
        detail = "Shell command · output appears in Sessions" if terminal else str(directory)
        row = Adw.ActionRow(title=GLib.markup_escape_text(name), subtitle=GLib.markup_escape_text(detail))
        play = button("Run", lambda *_: self._toggle_program(item), icon="media-playback-start-symbolic")
        play.set_valign(Gtk.Align.CENTER)
        view_log = Gtk.Button.new_from_icon_name("utilities-terminal-symbolic")
        view_log.set_tooltip_text(f"Open the latest log for {name}")
        view_log.set_valign(Gtk.Align.CENTER)
        view_log.add_css_class("flat")
        remove = Gtk.Button.new_from_icon_name("edit-delete-symbolic")
        remove.set_tooltip_text(f"Remove {name} from the list")
        remove.set_valign(Gtk.Align.CENTER)
        remove.add_css_class("flat")
        item = ProgramEntry(args, directory, name, terminal, row, play, view_log, detail)
        view_log.connect("clicked", lambda *_: self._open_program_log(item))
        remove.connect("clicked", lambda *_: self._remove_program(item))
        row.add_suffix(view_log)
        row.add_suffix(play)
        row.add_suffix(remove)
        self.programs.append(item)
        self.program_list.append(row)
        self.program_list.set_visible(True)
        self._refresh_service()
        return item

    def _toggle_program(self, item):
        if item.session_id is None:
            self._launch(item)
        else:
            self._stop_session(item.session_id)

    def _open_program_log(self, item):
        if item.last_log is not None:
            item.last_log.set_expanded(True)
            self._reveal_session(item.last_log)

    def _remove_program(self, item):
        if item.session_id is not None:
            self._toast("Stop this program before removing it.")
            return
        self.programs.remove(item)
        self.program_list.remove(item.row)
        self.program_list.set_visible(bool(self.programs))

    def _command_dialog(self, *_):
        running = bool(self.service and self.service.ready)
        dialog = Adw.MessageDialog(transient_for=self, heading="Terminal command",
                                   body="Run a noninteractive shell command inside a private tunnel. "
                                        "Its output appears under Sessions when logging is enabled.")
        command = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, monospace=True)
        command.set_tooltip_text("Type a shell command")
        scroll = Gtk.ScrolledWindow(child=command, min_content_height=94, min_content_width=280)
        folder = Gtk.Entry(text=self.folder.get_text(), placeholder_text=str(Path.home()))
        dialog.set_extra_child(box(scroll, label("Working folder", "field-hint"), folder, vertical=True, spacing=7))
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("run", "Run command" if running else "Add to list")
        dialog.set_response_appearance("run", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_close_response("cancel")

        def respond(_, response):
            if response != "run":
                return
            buffer = command.get_buffer()
            value = buffer.get_text(*buffer.get_bounds(), False).strip()
            if not value:
                self._toast("Enter a shell command.")
                return
            try:
                args, directory = app_command(shlex.join(["env", "BASH_ENV=/dev/null", "bash", "--noprofile", "--norc", "-c", value]),
                                              folder.get_text())
            except (TunnelError, OSError) as error:
                self._toast(error)
                return
            item = self._queue_program(args, directory, "Terminal command", terminal=True)
            if running and self.service is not None:
                self._launch(item)

        dialog.connect("response", respond)
        dialog.present()

    def _launch(self, item):
        service = self.service
        if self.closing or service is None or not service.ready or item.session_id is not None:
            return
        tunnel = service.tunnel
        args, directory, name = item.args, item.directory, item.name
        self.next_session += 1
        session_id = self.next_session
        item.session_id = session_id
        self.session_programs[session_id] = item
        session = self._create_session(session_id, name)
        self.sessions[session_id] = session
        item.last_log = session.row
        self.session_list.prepend(session.row)
        self.session_list.set_visible(True)
        self.empty_session.set_visible(False)
        self.latest_session_button.set_visible(True)
        if item.terminal:
            session.row.set_expanded(True)
        self._update_session_count()
        self._refresh_service()
        self._reveal_session(session.row)
        session.log.append("Tundock", f"Starting {name} · {service.detail}")

        def run():
            status = "Closed"
            failed = False
            process = None
            try:
                process = tunnel.spawn(
                    args, directory, stop=session.stop, output=session.log.append,
                    capture_enabled=session.log.is_enabled,
                )
                try:
                    GLib.idle_add(self._running, session_id, service, process)
                    started = time.monotonic()
                    while process.poll() is None and not session.stop.wait(0.2) and not service.stop.is_set():
                        pass
                    exit_code = process.returncode
                    if session.stop.is_set() or service.stop.is_set():
                        status = "Stopped"
                    elif exit_code:
                        failed = True
                        status = f"Program exited with status {exit_code}"
                    elif not item.terminal and time.monotonic() - started < 2:
                        status = "Exited quickly · an existing instance may have handled the launch"
                finally:
                    tunnel.stop_app(process)
            except InterruptedError:
                status = "Stopped"
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                if session.stop.is_set() or service.stop.is_set():
                    status = "Stopped"
                else:
                    failed = True
                    stage = "Session failed" if process is not None else "Startup failed"
                    status = f"{stage} · {error}"
            session.log.append("Tundock", status)
            GLib.idle_add(self._finished, session_id, status, failed)

        threading.Thread(target=run, daemon=True).start()

    def _create_session(self, session_id, name):
        row = Adw.ExpanderRow(title=GLib.markup_escape_text(name), subtitle="Starting · preparing a private network…")
        row.set_title_lines(1)
        row.set_subtitle_lines(2)
        log = SessionLog(enabled=self.get_application().session_logging_enabled())
        log_label = label("Live log" if log.is_enabled() else "Log paused", "field-hint")
        log_label.set_valign(Gtk.Align.CENTER)
        row.add_action(log_label)

        cancel = button("Stop", lambda *_: self._stop_session(session_id), "stop-button")
        cancel.set_valign(Gtk.Align.CENTER)
        row.add_action(cancel)

        check = button("Check exit IP", lambda *_: self._check_session_exit(session_id), "small-button")
        check.set_sensitive(False)
        network = label("Available after launch.", "field-hint", wrap=True)
        network.set_selectable(True)
        tools = box(check, network, spacing=10)
        drawer = box(tools, log.scroll, vertical=True, spacing=8)
        drawer.add_css_class("session-log-drawer")
        row.add_row(drawer)
        row.connect("notify::expanded", lambda *_: log.show_latest() if row.get_expanded() else None)
        return Session(row, threading.Event(), cancel, log, log_label, check, network)

    def _session_logging_changed(self, enabled):
        if self.service is not None:
            self.service.log.set_enabled(enabled)
        for session in self.sessions.values():
            session.log.set_enabled(enabled)
            session.log_label.set_text("Live log" if enabled else "Log paused")
        self._toast("Session logging resumed." if enabled else "Session logging paused.")

    def _reveal_session(self, row):
        def after_frame(*_):
            GLib.idle_add(scroll_to_row)
            return GLib.SOURCE_REMOVE

        def scroll_to_row():
            if row.get_parent() is self.session_list:
                valid, bounds = row.compute_bounds(self.main_scroll)
                if valid:
                    adjustment = self.main_scroll.get_vadjustment()
                    adjustment.set_value(adjustment.get_value() + bounds.get_y() - 12)
            return GLib.SOURCE_REMOVE

        row.add_tick_callback(after_frame)

    def _view_latest_session(self, *_):
        if row := self.session_list.get_first_child():
            row.set_expanded(True)
            self._reveal_session(row)

    def _running(self, session_id, service, process):
        session = self.sessions.get(session_id)
        if session and self.service is service and not session.stop.is_set():
            session.tunnel = service.tunnel
            session.process = process
            session.row.add_css_class("session-active")
            self._update_program_network(session, service)
            self._refresh_service()
        return GLib.SOURCE_REMOVE

    def _check_session_exit(self, session_id):
        session = self.sessions.get(session_id)
        service = self.service
        if (not session or not session.process or not service or not service.ready
                or session.check_stop is not None or session.stop.is_set()):
            return
        tunnel, process = session.tunnel, session.process
        check_stop = threading.Event()
        session.check_stop = check_stop
        session.check_button.set_sensitive(False)
        session.network.set_text("Checking exit IP…")

        def run():
            try:
                result = tunnel.check_exit(stop=check_stop, process=process)
                location = result.get("loc")
                address = f"{result['ip']} · {location}" if location else result["ip"]
                detail = f"Exit IP: {address}"
            except InterruptedError:
                return
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                detail = f"Exit IP check failed · {error}"
            GLib.idle_add(self._show_session_exit, session_id, check_stop, detail)

        self._refresh_service()
        threading.Thread(target=run, daemon=True).start()

    def _show_session_exit(self, session_id, check_stop, detail):
        session = self.sessions.get(session_id)
        if session and session.check_stop is check_stop and not session.stop.is_set():
            session.check_stop = None
            session.network.set_text(detail)
            session.log.append("Network", detail)
            self._refresh_service()
        return False

    def _cancel_exit_checks(self):
        for session in self.sessions.values():
            if session.check_stop is not None:
                session.check_stop.set()
                session.check_stop = None
                session.network.set_text("Exit IP check cancelled.")

    def _stop_session(self, session_id):
        if session := self.sessions.get(session_id):
            session.stop.set()
            if session.check_stop is not None:
                session.check_stop.set()
                session.check_stop = None
            session.button.set_sensitive(False)
            session.check_button.set_sensitive(False)
            session.row.set_subtitle("Stopping…")
            item = self.session_programs.get(session_id)
            if item is not None:
                item.play.set_sensitive(False)
                item.row.set_subtitle("Stopping…")

    def _finished(self, session_id, status, failed):
        if session := self.sessions.pop(session_id, None):
            session.stop.set()
            if session.check_stop is not None:
                session.check_stop.set()
            session.tunnel = None
            captured = session.log.is_enabled()
            session.log.set_enabled(False)
            session.log.flush(immediate=True)
            session.row.set_subtitle(GLib.markup_escape_text(status))
            session.row.remove_css_class("session-active")
            session.log_label.set_text("Log")
            session.check_button.set_sensitive(False)
            if session.check_stop is not None or not session.network.get_text().startswith("Exit IP:"):
                session.network.set_text("This session has ended.")
            if failed:
                session.row.add_css_class("session-failed")
                session.row.set_tooltip_text(status)
                if not self.closing:
                    if captured:
                        session.row.set_expanded(True)
                        self._toast("An isolated session failed. See its log for details.")
                    else:
                        self._toast("An isolated session failed while logging was paused.")
                    self._reveal_session(session.row)
            session.row.remove(session.button)
            dismiss = Gtk.Button.new_from_icon_name("window-close-symbolic")
            dismiss.set_tooltip_text("Remove finished session")
            dismiss.add_css_class("flat")
            dismiss.connect("clicked", lambda *_: self._remove_session_row(session.row))
            session.row.add_action(dismiss)
            self._update_session_count()
        if item := self.session_programs.pop(session_id, None):
            item.session_id = None
        self._refresh_service()
        self._complete_close()
        return False

    def _remove_session_row(self, row):
        self.session_list.remove(row)
        for item in self.programs:
            if item.last_log is row:
                item.last_log = None
                item.view_log.set_sensitive(False)
        empty = self.session_list.get_first_child() is None
        self.session_list.set_visible(not empty)
        self.empty_session.set_visible(empty)
        self.latest_session_button.set_visible(not empty)

    def _update_session_count(self):
        count = len(self.sessions)
        self.active_count.set_text("No active sessions" if not count else
                                   f"{count} active {'session' if count == 1 else 'sessions'}")

    def _browse(self, *_):
        dialog = Gtk.FileChooserNative(title="Choose an executable", transient_for=self,
                                       action=Gtk.FileChooserAction.OPEN, accept_label="Choose", cancel_label="Cancel")

        def response(chooser, result):
            if result == Gtk.ResponseType.ACCEPT and (file := chooser.get_file()) and file.get_path():
                executable = Path(file.get_path())
                self.command.set_text(shlex.quote(str(executable)))
                self.folder.set_text(str(executable.parent))
                self.selected_preset = None
                self._queue_from_form()
            chooser.destroy()

        dialog.connect("response", response)
        dialog.show()

    def _choose_application(self, *_):
        dialog = Gtk.Window(title="Installed applications", modal=True, transient_for=self,
                            default_width=500, default_height=500)
        search = Gtk.SearchEntry(placeholder_text="Find an application")
        listing = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listing.add_css_class("boxed-list")
        scroll = Gtk.ScrolledWindow(vexpand=True, hscrollbar_policy=Gtk.PolicyType.NEVER, child=listing)
        wrap = box(search, scroll, vertical=True, spacing=12)
        for edge in ("top", "bottom", "start", "end"):
            getattr(wrap, f"set_margin_{edge}")(18)
        dialog.set_child(wrap)
        apps = sorted((info for info in Gio.AppInfo.get_all() if isinstance(info, Gio.DesktopAppInfo)
                       and info.should_show() and info.get_commandline()),
                      key=lambda info: info.get_display_name().casefold())

        def populate(*_):
            clear_list(listing)
            query = search.get_text().casefold().strip()
            for info in apps:
                if query not in f"{info.get_display_name()} {info.get_executable()}".casefold():
                    continue
                row = Adw.ActionRow(title=GLib.markup_escape_text(info.get_display_name()),
                                    subtitle=GLib.markup_escape_text(info.get_executable()), activatable=True)
                if icon := info.get_icon():
                    row.add_prefix(Gtk.Image.new_from_gicon(icon))
                row.connect("activated", choose, info)
                listing.append(row)
            if listing.get_first_child() is None:
                listing.append(Adw.ActionRow(title="No matching applications"))

        def choose(_, info):
            try:
                self.command.set_text(desktop_command(info))
                self.folder.set_text(info.get_string("Path") or "")
            except (TunnelError, ValueError) as error:
                dialog.close()
                self._toast(error)
                return
            self.selected_preset = None
            dialog.close()
            self._queue_from_form(display_name=info.get_display_name())

        search.connect("search-changed", populate)
        populate()
        dialog.present()

    def _render_presets(self):
        clear_list(self.preset_list)
        if not self.presets:
            empty = label("Save frequently used programs and proxy settings here.", "sidebar-footnote", wrap=True)
            self.preset_list.append(empty)
            self.preset_list.get_first_child().set_activatable(False)
        for preset in self.presets:
            row = Adw.ActionRow(title=GLib.markup_escape_text(preset.name),
                                subtitle=GLib.markup_escape_text(preset.address), activatable=True)
            row.set_title_lines(1)
            row.set_subtitle_lines(1)
            remove = Gtk.Button.new_from_icon_name("edit-delete-symbolic")
            remove.add_css_class("flat")
            remove.set_tooltip_text(f"Delete {preset.name} preset")
            remove.connect("clicked", lambda _, item=preset: self._remove_preset(item))
            row.add_suffix(remove)
            row.connect("activated", self._load_preset, preset)
            self.preset_list.append(row)

    def _load_preset(self, _, preset):
        self.selected_preset = preset.name
        self.proxy.set_text(preset.address)
        self.username.set_text("")
        self.password.set_text("")
        self.command.set_text(preset.command)
        self.folder.set_text(preset.directory)
        self.resolver.set_selected(tuple(RESOLVERS).index(preset.options.resolver))
        self.udp_policy.set_selected(POLICIES.index(preset.options.udp))
        self.ipv6_policy.set_selected(POLICIES.index(preset.options.ipv6))
        self.desktop.set_active(preset.options.desktop_services)

    def _save_preset(self, *_):
        if self.preset_error:
            self._toast(self.preset_error)
            return
        try:
            proxy, options = self._input()
            args, _ = app_command(self.command.get_text(), self.folder.get_text())
        except (TunnelError, OSError) as error:
            self._toast(error)
            return
        dialog = Adw.MessageDialog(transient_for=self, heading="Save a preset",
                                   body="The program and proxy address are saved. Proxy credentials are omitted.")
        name = Gtk.Entry(text=self.selected_preset or Path(args[0]).name, max_length=60, activates_default=True)
        dialog.set_extra_child(name)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.set_close_response("cancel")

        def save_response(_, response):
            if response != "save":
                return
            title = name.get_text().strip()
            if not title:
                self._toast("Enter a name for the preset.")
                return
            preset = storage.Preset(title, proxy.address, self.command.get_text(), self.folder.get_text(), options)
            updated = [item for item in self.presets if item.name != title]
            updated.append(preset)
            updated.sort(key=lambda item: item.name.casefold())
            if self._store(updated):
                self.selected_preset = title
                self._toast("Preset saved.")

        dialog.connect("response", save_response)
        dialog.present()

    def _remove_preset(self, preset):
        if self._store([item for item in self.presets if item != preset]):
            if self.selected_preset == preset.name:
                self.selected_preset = None
            self._toast("Preset deleted.")

    def _store(self, presets):
        try:
            storage.save(presets)
        except OSError as error:
            self._toast(f"Couldn't save presets: {error.strerror}")
            return False
        self.presets = presets
        if not any(preset.name == self.selected_preset for preset in presets):
            self.selected_preset = None
        self._render_presets()
        return True

    def _close_requested(self, *_):
        return self.get_application()._request_close(self)

    def _begin_close(self):
        self.closing = True
        self._cancel_test()
        if self.service is not None:
            self.service.stop.set()
            self.service.commands.put(("quit", None))
        for session_id in self.sessions:
            self._stop_session(session_id)
        self._refresh_service()
        self.set_sensitive(False)
        self._complete_close()

    def _complete_close(self):
        if self.closing and self.service is None and not self.sessions and self.test_stop is None:
            self.get_application()._window_finished()
            self.destroy()


class Application(Adw.Application):
    def __init__(self, new_instance=False):
        self.portable = os.getenv("TUNDOCK_PORTABLE") == "1"
        flags = Gio.ApplicationFlags.NON_UNIQUE if new_instance else Gio.ApplicationFlags.DEFAULT_FLAGS
        super().__init__(application_id=APP_ID, flags=flags)
        self.window = None
        self.closing = False
        self.background = False
        self.close_dialog = None
        logging_action = Gio.SimpleAction.new_stateful("session-logging", None, GLib.Variant.new_boolean(True))
        logging_action.connect("change-state", self._change_session_logging)
        self.add_action(logging_action)
        for name, callback in (("requirements", self.requirements), ("about", self.about), ("quit", self._quit_action)):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def session_logging_enabled(self):
        return self.lookup_action("session-logging").get_state().get_boolean()

    def _change_session_logging(self, action, state):
        action.set_state(state)
        if self.window is not None:
            self.window._session_logging_changed(state.get_boolean())

    def do_startup(self):
        Adw.Application.do_startup(self)
        css = Gtk.CssProvider()
        css.load_from_path(str(ROOT / "style.css"))
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css,
                                                 Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(ROOT))
        Gtk.Window.set_default_icon_name(APP_ID)
        self.get_style_manager().set_color_scheme(Adw.ColorScheme.DEFAULT)
        for termination_signal in (signal.SIGTERM, signal.SIGINT):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, termination_signal, self._shutdown_requested)

    def _quit_action(self, *_):
        if self.window is not None:
            self._request_close(self.window, quit_application=True)

    def _request_close(self, requester, *, quit_application=False):
        if self.closing:
            return True
        service = requester.service
        programs_running = bool(requester.sessions)
        if not (programs_running or requester.test_stop or (service and (service.active or service.pending))):
            self._shutdown_requested()
            return True
        if self.close_dialog:
            self.close_dialog.present()
            return True
        can_background = (not quit_application and programs_running
                          and not self.get_flags() & Gio.ApplicationFlags.NON_UNIQUE)
        body = "Quit Tundock to close the programs and stop the private network."
        if can_background:
            body += " You can also keep the programs running in the background and open Tundock again to manage them."
        dialog = Adw.MessageDialog(transient_for=requester, heading="Close Tundock?", body=body)
        dialog.add_response("cancel", "Keep open")
        if can_background:
            dialog.add_response("background", "Keep running")
            dialog.set_response_appearance("background", Adw.ResponseAppearance.SUGGESTED)
        dialog.add_response("stop", "Stop and quit")
        dialog.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def respond(_, response):
            self.close_dialog = None
            if response == "stop":
                self._shutdown_requested()
            elif response == "background":
                self._hide_window()

        self.close_dialog = dialog
        dialog.connect("response", respond)
        dialog.present()
        return True

    def _hide_window(self):
        if not self.background:
            self.hold()
            self.background = True
        self.window.set_visible(False)

    def _window_finished(self):
        self.window = None
        if self.background:
            self.background = False
            self.release()

    def _shutdown_requested(self):
        if self.closing:
            return GLib.SOURCE_CONTINUE
        self.closing = True
        if self.window is not None:
            self.window._begin_close()
        else:
            self.quit()
        return GLib.SOURCE_CONTINUE

    def do_activate(self):
        if self.closing:
            return
        if self.window is None:
            self.window = Window(self)
        self.window.present()
        if self.background:
            self.background = False
            self.release()

    def requirements(self, *_):
        try:
            dependency_paths()
            subtitle = "Required executables and the TUN device are available. Run a connection test to verify permissions."
        except TunnelError as error:
            subtitle = str(error)
        tools = ("This executable contains Tundock and its proxy engine. It uses the host's GTK 4, libadwaita, "
                 "bubblewrap, util-linux and iproute2." if self.portable else
                 "GTK 4, libadwaita, sing-box 1.14+, bubblewrap, util-linux and iproute2.")
        dialog = Adw.MessageDialog(transient_for=self.get_active_window(), heading="System requirements",
                                   body=f"{subtitle}\n\n{tools}")
        dialog.add_response("okay", "Close")
        dialog.present()

    def about(self, *_):
        theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
        icon = APP_ID if theme.has_icon(APP_ID) else "tundock"
        dialog = Adw.AboutWindow(transient_for=self.get_active_window(), application_name="Tundock",
                                 version=__version__, application_icon=icon,
                                 comments=("Portable edition · per-application proxy routing for Linux."
                                           if self.portable else "Per-application proxy routing for Linux."))
        dialog.present()
