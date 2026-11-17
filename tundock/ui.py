"""Native GTK desktop interface."""

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
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
from gi.repository import Adw, Gdk, GdkPixbuf, Gio, GLib, Gtk, Pango

from . import __version__, storage
from .core import (
    ROOT, POLICIES, RESOLVERS, Options, Proxy, Report, Tunnel, TunnelError,
    app_command, dependency_paths, network_modes,
)
from .diagnostics import probe
from .launchcheck import flatpak_target, launch_target

APP_ID = "io.github.tundock.Tundock"
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

    def __init__(self):
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

    def append(self, source, line):
        text = f"[{source}] {line.rstrip()}".replace("\r", " ").replace("\n", " ").replace("\0", "�")
        if len(text) > self.max_columns:
            text = text[:self.max_columns - 1] + "…"
        with self.lock:
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
    checking: bool = False


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Tundock", default_width=1090, default_height=795)
        self.set_size_request(760, 560)
        self.add_css_class("tundock")
        self.report = None
        self.report_key = None
        self.test_stop = None
        self.closing = False
        self.close_dialog = None
        self.sessions = {}
        self.next_session = 0
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
        menu.append("Requirements", "app.requirements")
        menu.append("About Tundock", "app.about")
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu,
                                       tooltip_text="Tundock menu"))
        brand_icon = self._brand_picture(24)
        brand_icon.add_css_class("brand-icon")
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

        heading = box(label("Launch an isolated app", "headline", wrap=True),
                      label("Choose a proxy and a program. Other apps keep their current connection.",
                            "subheading", wrap=True), vertical=True, spacing=7)
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
        proxy_hint = label("SOCKS5 or HTTP(S) CONNECT", "field-hint", wrap=True)
        proxy_hint.set_hexpand(True)
        save_proxy = button("Save proxy", self._save_bookmark, "small-button", icon="bookmark-new-symbolic")
        proxy_card = box(box(proxy_title, self.test, spacing=12), self.proxy,
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
        app_card = box(label("Program", "section-title"), self.command,
                       box(pick, browse, spacing=8),
                       label("Close an existing copy before launching a single-instance app.", "field-hint", wrap=True),
                       vertical=True, spacing=9)
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
        launch = button("Launch isolated", self._launch, "launch-button", icon="media-playback-start-symbolic")
        self.latest_session_button = button(
            "Latest log", self._view_latest_session, icon="utilities-terminal-symbolic",
        )
        self.latest_session_button.set_visible(False)
        actions = box(self.latest_session_button, Gtk.Box(hexpand=True), save, launch, spacing=9)
        footer = Adw.Clamp(maximum_size=965, tightening_threshold=785, child=actions)
        footer.add_css_class("action-bar")

        self.session_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.session_list.add_css_class("boxed-list")
        self.empty_session = label("Open a session row to see its live log.", "field-hint", wrap=True)
        sessions = box(label("Sessions", "section-title"), self.empty_session, self.session_list,
                       vertical=True, spacing=9)

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
        self.protocol_plan.set_text("Next launch · " + " · ".join(modes))
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

    def _launch(self, *_):
        if self.closing:
            return
        try:
            proxy, options = self._input()
            args, directory = app_command(self.command.get_text(), self.folder.get_text())
            flatpak = flatpak_target(args)
            dependency_paths()
        except (TunnelError, OSError, ValueError) as error:
            self._toast(error)
            return
        report = self.report if self.report_key == (proxy, options) else Report()
        udp, ipv6 = network_modes(proxy, options, report)
        self.next_session += 1
        session_id = self.next_session
        target = launch_target(args) or args
        name = flatpak[1] if flatpak else Path(target[0]).name
        mode = f"{proxy.address}  ·  UDP {'on' if udp else 'blocked'}  ·  IPv6 {'on' if ipv6 else 'blocked'}"
        session = self._create_session(session_id, name)
        self.sessions[session_id] = session
        self.session_list.prepend(session.row)
        self.session_list.set_visible(True)
        self.empty_session.set_visible(False)
        self.latest_session_button.set_visible(True)
        self._update_session_count()
        self._reveal_session(session.row)
        self._toast(f"Starting {name} in a private network.")
        session.log.append("Tundock", f"Starting {name} · {mode}")

        def run():
            status = "Closed"
            failed = False
            launched = False
            try:
                with Tunnel(proxy, options, udp=udp, ipv6=ipv6, output=session.log.append) as tunnel:
                    tunnel.start(session.stop)
                    if session.stop.is_set():
                        raise InterruptedError("Session cancelled.")
                    tunnel.launch(args, directory, stop=session.stop)
                    started = time.monotonic()
                    try:
                        exit_code = tunnel.app.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        launched = True
                        GLib.idle_add(self._running, session_id, mode, tunnel)
                        exit_code = tunnel.follow(session.stop)
                    if session.stop.is_set():
                        status = "Stopped"
                    elif exit_code:
                        failed = True
                        stage = "Session failed" if launched else "Startup failed"
                        status = f"{stage} · program or isolation wrapper exited with status {exit_code}"
                    elif time.monotonic() - started < 2:
                        status = "Exited quickly · an existing instance may have handled the launch"
            except InterruptedError:
                status = "Stopped"
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                failed = True
                stage = "Session failed" if launched else "Startup failed"
                status = f"{stage} · {error}"
            session.log.append("Tundock", status)
            GLib.idle_add(self._finished, session_id, status, failed)

        threading.Thread(target=run, daemon=True).start()

    def _create_session(self, session_id, name):
        row = Adw.ExpanderRow(title=GLib.markup_escape_text(name), subtitle="Starting · preparing a private network…")
        row.set_title_lines(1)
        row.set_subtitle_lines(2)
        log_label = label("Live log", "field-hint")
        log_label.set_valign(Gtk.Align.CENTER)
        row.add_action(log_label)

        cancel = button("Stop", lambda *_: self._stop_session(session_id), "stop-button")
        cancel.set_valign(Gtk.Align.CENTER)
        row.add_action(cancel)

        log = SessionLog()
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

    def _running(self, session_id, mode, tunnel):
        session = self.sessions.get(session_id)
        if session and not session.stop.is_set():
            session.tunnel = tunnel
            session.row.set_subtitle(GLib.markup_escape_text(f"Running · {mode}"))
            session.row.add_css_class("session-active")
            session.check_button.set_sensitive(True)
            session.network.set_text("Checks this session through Cloudflare HTTPS.")
        return False

    def _check_session_exit(self, session_id):
        session = self.sessions.get(session_id)
        if not session or not session.tunnel or session.checking or session.stop.is_set():
            return
        tunnel = session.tunnel
        session.checking = True
        session.check_button.set_sensitive(False)
        session.network.set_text("Checking exit IP…")

        def run():
            try:
                result = tunnel.check_exit(stop=session.stop)
                location = result.get("loc")
                address = f"{result['ip']} · {location}" if location else result["ip"]
                detail = f"Exit IP: {address}"
            except InterruptedError:
                return
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                detail = f"Exit IP check failed · {error}"
            GLib.idle_add(self._show_session_exit, session_id, detail)

        threading.Thread(target=run, daemon=True).start()

    def _show_session_exit(self, session_id, detail):
        session = self.sessions.get(session_id)
        if session and not session.stop.is_set():
            session.checking = False
            session.network.set_text(detail)
            session.log.append("Network", detail)
            session.check_button.set_sensitive(True)
        return False

    def _stop_session(self, session_id):
        if session := self.sessions.get(session_id):
            session.stop.set()
            session.button.set_sensitive(False)
            session.check_button.set_sensitive(False)
            session.row.set_subtitle("Stopping…")

    def _finished(self, session_id, status, failed):
        if session := self.sessions.pop(session_id, None):
            session.stop.set()
            session.tunnel = None
            session.log.flush(immediate=True)
            session.row.set_subtitle(GLib.markup_escape_text(status))
            session.row.remove_css_class("session-active")
            session.log_label.set_text("Log")
            session.check_button.set_sensitive(False)
            if session.checking or not session.network.get_text().startswith("Exit IP:"):
                session.network.set_text("This session has ended.")
            if failed:
                session.row.add_css_class("session-failed")
                session.row.set_tooltip_text(status)
                if not self.closing:
                    session.row.set_expanded(True)
                    self._reveal_session(session.row)
                    self._toast("An isolated session failed. See its log for details.")
            session.row.remove(session.button)
            dismiss = Gtk.Button.new_from_icon_name("window-close-symbolic")
            dismiss.set_tooltip_text("Remove finished session")
            dismiss.add_css_class("flat")
            dismiss.connect("clicked", lambda *_: self._remove_session_row(session.row))
            session.row.add_action(dismiss)
            self._update_session_count()
        self._complete_close()
        return False

    def _remove_session_row(self, row):
        self.session_list.remove(row)
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
        self._render_presets()
        return True

    def _close_requested(self, *_):
        if self.closing:
            return True
        if not self.sessions:
            if self.test_stop:
                self._begin_close()
                return True
            return False
        if self.close_dialog:
            self.close_dialog.present()
            return True
        dialog = Adw.MessageDialog(transient_for=self, heading="Close isolated sessions?",
                                   body="Closing Tundock will stop the programs it launched.")
        dialog.add_response("cancel", "Keep open")
        dialog.add_response("stop", "Stop and close")
        dialog.set_response_appearance("stop", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def respond(_, response):
            self.close_dialog = None
            if response == "stop":
                self._begin_close()

        self.close_dialog = dialog
        dialog.connect("response", respond)
        dialog.present()
        return True

    def _begin_close(self):
        self.closing = True
        self._cancel_test()
        for session_id in self.sessions:
            self._stop_session(session_id)
        self.set_sensitive(False)
        self._complete_close()

    def _complete_close(self):
        if self.closing and not self.sessions and self.test_stop is None:
            self.destroy()


class Application(Adw.Application):
    def __init__(self):
        self.portable = os.getenv("TUNDOCK_PORTABLE") == "1"
        version = re.sub(r"[^A-Za-z0-9_]", "_", __version__)
        app_id = f"{APP_ID}.Portable.v{version}" if self.portable else APP_ID
        super().__init__(application_id=app_id)
        for name, callback in (("requirements", self.requirements), ("about", self.about)):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def do_startup(self):
        Adw.Application.do_startup(self)
        css = Gtk.CssProvider()
        css.load_from_path(str(ROOT / "style.css"))
        Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), css,
                                                 Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(ROOT))
        Gtk.Window.set_default_icon_name("tundock")
        self.get_style_manager().set_color_scheme(Adw.ColorScheme.PREFER_DARK)
        for termination_signal in (signal.SIGTERM, signal.SIGINT):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, termination_signal, self._shutdown_requested)

    def _shutdown_requested(self):
        window = self.get_active_window()
        if isinstance(window, Window):
            if not window.closing:
                window._begin_close()
        else:
            self.quit()
        return GLib.SOURCE_CONTINUE

    def do_activate(self):
        window = self.get_active_window() or Window(self)
        window.present()

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
        dialog = Adw.AboutWindow(transient_for=self.get_active_window(), application_name="Tundock",
                                 version=__version__, application_icon="tundock",
                                 comments=("Portable edition · per-application proxy routing for Linux."
                                           if self.portable else "Per-application proxy routing for Linux."))
        dialog.present()
