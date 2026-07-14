"""
repl.py - The Hypernova interactive shell.

Launch with `hypernova` and you land in a live prompt. Everything is driven
by slash-commands: capture -> select -> mark -> attack -> filter -> review
-> export, all without leaving the terminal.
"""

import json
import shlex
import threading
import time

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.table import Table
from rich.live import Live

from . import selector, report
from .db import DB
from .engine import AttackEngine, marker_count, total_request_count, MarkerError

console = Console()

# ---- pixel-art mascot -------------------------------------------------------
# "Nova", the Hypernova star-buddy, shown at the top of the shell like the
# Claude Code mascot. Rendered with rich markup so it lights up in colour.
MASCOT = r"""
[bold yellow]        \ [bright_white]:[/bright_white] /        [/bold yellow]
[bold yellow]      `. [bright_cyan]▄▄▄[/bright_cyan] .'       [/bold yellow]
[bold magenta]  ─ ─ [bright_cyan]▟█[bright_white]●[/bright_white] [bright_white]●[/bright_white]█▙[/bright_cyan] ─ ─   [/bold magenta]
[bold magenta]      [bright_cyan]▜█[bright_yellow] ▼ [/bright_yellow]█▛[/bright_cyan]       [/bold magenta]
[bold yellow]      .' [bright_cyan]▀▀▀[/bright_cyan] '.       [/bold yellow]
[bold yellow]        / [bright_white]:[/bright_white] \        [/bold yellow]
"""

BANNER_TEXT = (
    "[bold bright_cyan]H Y P E R N O V A[/bold bright_cyan]  "
    "[dim]v1.0[/dim]\n"
    "[dim]terminal-native HTTP intruder — capture · mark · attack · review[/dim]\n"
    "[dim]type [/dim][bold]/help[/bold][dim] for commands, [/dim][bold]/capture[/bold]"
    "[dim] to start the proxy, [/dim][bold]/history[/bold][dim] to browse traffic, [/dim]"
    "[bold]/scope[/bold][dim] to focus on a target[/dim]"
)

# prompt_toolkit style for the bottom bar + prompt.
PROMPT_STYLE = Style.from_dict({
    "bottom-toolbar": "bg:#1b1f27 #8b949e",
    "bt-on": "bg:#1b1f27 #3fb950 bold",
    "bt-off": "bg:#1b1f27 #6e7681",
    "bt-key": "bg:#1b1f27 #58a6ff bold",
    "bt-sess": "bg:#1b1f27 #d2a8ff bold",
    "prompt-arrow": "#3fb950 bold",
    "prompt-ctx": "#58a6ff",
})

COMMANDS = [
    "/help", "/capture", "/capture stop", "/capture status",
    "/paste", "/history", "/select", "/mark", "/attack",
    "/scope", "/scope add", "/scope rm", "/scope list", "/scope clear",
    "/scope on", "/scope off",
    "/filter", "/filter-ad", "/filter-da", "/filter-rv",
    "/pause", "/resume", "/repeat", "/payload", "/change-method",
    "/fresh", "/end", "/sessions", "/open", "/exit",
]

ATTACK_TYPES = ["sniper", "pitchfork", "battering_ram", "clusterbomb"]

HELP_TEXT = """
[bold]Capture & selection[/bold]
  /capture [port]        Start the MITM capture proxy (default port 8090)
  /capture status        Show live capture count / last URL
  /capture stop          Stop the proxy (captured requests stay saved)
  /paste                 Paste a raw request manually (no proxy needed)
  /history               Burp-style proxy HTTP history — expand any request
                         to see all headers, params and values (scope-aware)
  /select                Browse captured traffic and pick a request to attack
  /mark                  Edit the selected request, wrap fuzz points in §§

[bold]Scope (Burp-style target scope)[/bold]
  /scope                 Show the current scope and status
  /scope add <pattern>   Add a host or URL pattern (e.g. example.com, *.x.com,
                         example.com/api).  Only in-scope requests are shown.
  /scope rm <pattern>    Remove a pattern
  /scope list            List patterns
  /scope clear           Remove all patterns
  /scope on | off        Enable / disable scope filtering (patterns are kept)

[bold]Attacking[/bold]
  /attack                Configure attack type + payloads, then run it
  /pause                 Pause the running attack (checkpointed to disk)
  /resume                Resume a paused attack from where it left off
  /repeat                Re-run the last attack config as a new session
  /payload               Re-open payload selection without rebuilding the attack
  /change-method         Switch attack type for the current request

[bold]Reviewing results[/bold]
  /filter ["kw"]         Sort ascending (default), or show rows containing kw
  /filter-ad             Explicit ascending sort
  /filter-da             Descending sort
  /filter-rv "kw"        Reverse filter — rows NOT containing kw
  /sessions              List all past attack sessions
  /open <session_id>     Reopen a past session's results

[bold]Session control[/bold]
  /fresh                 Wipe current session state, start from scratch
  /end                   Stop the current attack for good, then export
  /exit                  Exit Hypernova
"""


class Shell:
    def __init__(self, db_path=None):
        self.db = DB(db_path) if db_path else DB()
        self.session = PromptSession(
            completer=WordCompleter(COMMANDS, sentence=True),
            complete_while_typing=True,
            bottom_toolbar=self._bottom_toolbar,
            refresh_interval=0.5,   # keeps the live capture counter ticking
            style=PROMPT_STYLE,
        )
        self.current_request = None       # dict: method/url/headers/body (with §§)
        self.current_session_id = None
        self.current_engine = None
        self.current_sort_col = "request_no"
        self.current_sort_desc = False
        self.current_keyword = None
        self.current_reverse_kw = False
        self.last_attack_config = None    # (attack_type, payload_lists) for /repeat
        self._live_thread = None
        self.capture_proxy = None
        # Target scope: patterns persisted in the DB; a runtime toggle to
        # switch filtering on/off without discarding the patterns.
        self.scope_enabled = True

    # ---------------- main loop ----------------

    def run(self):
        self._show_banner()
        while True:
            try:
                line = self.session.prompt(self._prompt_fragments()).strip()
            except EOFError:
                self._exit()
                break
            except KeyboardInterrupt:
                # Ctrl-C at the prompt clears the line instead of quitting —
                # friendlier, and matches most modern shells.
                continue
            if not line:
                continue
            self.dispatch(line)

    def _show_banner(self):
        # highlight=False stops rich from recolouring digits/punctuation inside
        # the hand-styled art and banner.
        console.print(MASCOT, highlight=False)
        console.print(BANNER_TEXT, highlight=False)
        console.print()

    def _prompt_fragments(self):
        """The styled input prompt. Shows the active context (selected request
        or session) inline so the user always knows where they are."""
        ctx = ""
        if self.current_session_id:
            ctx = f"session:{self.current_session_id} "
        elif self.current_request:
            ctx = "request-ready "
        return HTML(f"<prompt-ctx>{ctx}</prompt-ctx><prompt-arrow>&gt; </prompt-arrow>")

    def _bottom_toolbar(self):
        """Status bar pinned to the very bottom of the terminal, refreshed
        twice a second so live capture counts and attack progress update in
        place while you type."""
        segs = [("class:bt-key", " Hypernova ")]

        # Capture proxy status
        if self.capture_proxy and getattr(self.capture_proxy, "running", False):
            n = self.capture_proxy.captured_count
            segs.append(("class:bt-on", f"● proxy:{self.capture_proxy.port} "))
            segs.append(("class:bottom-toolbar", f"captured:{n} "))
        else:
            segs.append(("class:bt-off", "○ proxy:off "))

        # Scope indicator
        try:
            n_scope = len(self.db.list_scope())
        except Exception:
            n_scope = 0
        if n_scope and self.scope_enabled:
            segs.append(("class:bt-key", f"⊙ scope:{n_scope} "))

        # Selection / session context
        if self.current_request:
            m = self.current_request.get("method", "?")
            try:
                mk = marker_count(self.current_request)
            except Exception:
                mk = 0
            segs.append(("class:bottom-toolbar", f"| req:{m} §×{mk} "))
        if self.current_session_id:
            segs.append(("class:bt-sess", f"| session:{self.current_session_id} "))
            if self.current_engine and self.current_engine.is_alive():
                segs.append(("class:bt-on", "running "))

        segs.append(("class:bottom-toolbar", "| /help  /capture  /history  /scope  /attack  /exit "))
        return segs

    def dispatch(self, line):
        try:
            parts = shlex.split(line)
        except ValueError as e:
            console.print(f"[red]Parse error: {e}[/red]")
            return
        cmd, args = parts[0], parts[1:]

        handlers = {
            "/help": self.cmd_help,
            "/capture": self.cmd_capture,
            "/paste": self.cmd_paste,
            "/history": self.cmd_history,
            "/scope": self.cmd_scope,
            "/select": self.cmd_select,
            "/mark": self.cmd_mark,
            "/attack": self.cmd_attack,
            "/filter": self.cmd_filter,
            "/filter-ad": self.cmd_filter_ad,
            "/filter-da": self.cmd_filter_da,
            "/filter-rv": self.cmd_filter_rv,
            "/pause": self.cmd_pause,
            "/resume": self.cmd_resume,
            "/repeat": self.cmd_repeat,
            "/payload": self.cmd_payload,
            "/change-method": self.cmd_change_method,
            "/fresh": self.cmd_fresh,
            "/end": self.cmd_end,
            "/sessions": self.cmd_sessions,
            "/open": self.cmd_open,
            "/exit": self._exit,
        }
        handler = handlers.get(cmd)
        if not handler:
            console.print(f"[yellow]Unknown command: {cmd} (try /help)[/yellow]")
            return
        handler(args)

    # ---------------- capture / selection ----------------

    def cmd_help(self, args):
        console.print(HELP_TEXT)

    def cmd_capture(self, args):
        from . import capture

        # Subcommands: /capture stop | /capture status
        if args and args[0] in ("stop", "status"):
            self._capture_subcommand(args[0])
            return

        if not capture.MITMPROXY_AVAILABLE:
            console.print("[red]mitmproxy is not installed[/red] (the optional "
                          "capture engine).\n"
                          "Install it with:  [bold]pipx inject hypernova mitmproxy[/bold]\n"
                          "  (or, inside a venv:  [bold]pip install mitmproxy[/bold])\n"
                          "Meanwhile, [bold]/paste[/bold] lets you load a request by hand "
                          "with no proxy needed.")
            return

        if self.capture_proxy and self.capture_proxy.running:
            console.print(f"[yellow]Capture already running on port "
                          f"{self.capture_proxy.port}.[/yellow] Use "
                          f"[bold]/capture stop[/bold] first to change ports.")
            return

        try:
            port = int(args[0]) if args else 8090
        except ValueError:
            console.print(f"[red]'{args[0]}' is not a valid port.[/red]")
            return

        console.print(f"[dim]Starting capture proxy on 127.0.0.1:{port}…[/dim]")
        self.capture_proxy = capture.CaptureProxy(self.db, port=port)
        self.capture_proxy.start()
        if self.capture_proxy.startup_error:
            console.print(f"[red]Proxy failed to start:[/red] "
                          f"{self.capture_proxy.startup_error}")
            self.capture_proxy = None
            return
        console.print("[bold green]✓ Capture proxy is live.[/bold green]")
        console.print(f"[green]  1.[/green] Point your browser/FoxyProxy at "
                      f"[bold]127.0.0.1:{port}[/bold] (HTTP + HTTPS)")
        console.print(f"[green]  2.[/green] In the proxied browser, open "
                      f"[bold]http://mitm.it[/bold] and install Hypernova's CA cert "
                      f"(one-time, same flow as Burp)")
        console.print(f"[green]  3.[/green] Browse the target — requests stream into "
                      f"the DB live (watch the [bold]captured:[/bold] counter below). "
                      f"Then [bold]/select[/bold] one.")

    def _capture_subcommand(self, sub):
        if not self.capture_proxy or not self.capture_proxy.running:
            console.print("[yellow]No capture proxy is running.[/yellow]")
            return
        if sub == "status":
            console.print(f"[green]Proxy live on 127.0.0.1:{self.capture_proxy.port} — "
                          f"captured {self.capture_proxy.captured_count} request(s).[/green]")
            if self.capture_proxy.last_url:
                console.print(f"[dim]  last: {self.capture_proxy.last_url}[/dim]")
        elif sub == "stop":
            n = self.capture_proxy.captured_count
            self.capture_proxy.stop()
            self.capture_proxy = None
            console.print(f"[yellow]Capture stopped.[/yellow] "
                          f"{n} request(s) are saved — use [bold]/select[/bold] to pick one.")

    def cmd_paste(self, args):
        console.print("[dim]Paste the raw HTTP request (method + URL on first "
                      "line, headers, blank line, body). End with a blank line "
                      "on its own after the body.[/dim]")
        lines = []
        while True:
            line = self.session.prompt("")
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
        raw = "\n".join(lines).rstrip("\n")
        parsed = self._parse_raw_request(raw)
        capture_id = self.db.insert_captured(
            parsed["method"], parsed["url"], parsed["headers"], parsed["body"]
        )
        console.print(f"[green]Stored as capture #{capture_id}[/green]. Use /select to pick it.")

    def _parse_raw_request(self, raw):
        lines = raw.split("\n")
        first = lines[0].split(" ")
        method = first[0] if first else "GET"
        if len(first) >= 3 and first[-1].upper().startswith("HTTP/"):
            url = " ".join(first[1:-1])
        elif len(first) >= 2:
            url = " ".join(first[1:])
        else:
            url = ""
        headers, i = {}, 1
        while i < len(lines) and lines[i].strip() != "":
            if ":" in lines[i]:
                k, _, v = lines[i].partition(":")
                headers[k.strip()] = v.strip()
            i += 1
        body = "\n".join(lines[i + 1:]) if i + 1 < len(lines) else ""
        return {"method": method, "url": url, "headers": headers, "body": body}

    def _active_scope(self):
        """Return the list of scope patterns to filter by, or None when scope
        filtering is off / empty (meaning: show everything)."""
        if not self.scope_enabled:
            return None
        patterns = self.db.list_scope()
        return patterns or None

    def cmd_history(self, args):
        """Burp-style proxy HTTP history: list captured traffic, expand any
        request to see all its headers/params/values, and optionally send one
        into the attack flow."""
        capture_id = selector.browse_history(self.db, self._active_scope())
        if capture_id is None:
            return
        row = self.db.get_captured(capture_id)
        self.current_request = selector.request_from_capture(row)
        console.print(f"[green]Selected capture #{capture_id}: "
                      f"{self.current_request['method']} {self.current_request['url']}[/green]")
        console.print("[dim]Use /mark to wrap fuzz points in §§, then /attack.[/dim]")

    def cmd_scope(self, args):
        sub = args[0].lower() if args else "list"
        rest = " ".join(args[1:]).strip()

        if sub == "add":
            if not rest:
                console.print("[yellow]Usage: /scope add <host-or-url-pattern>[/yellow]")
                return
            added = self.db.add_scope(rest)
            self.scope_enabled = True
            console.print(f"[green]{'Added' if added else 'Already in scope'}:[/green] {rest}")
            self._show_scope()
        elif sub in ("rm", "remove", "del"):
            if not rest:
                console.print("[yellow]Usage: /scope rm <pattern>[/yellow]")
                return
            removed = self.db.remove_scope(rest)
            console.print(f"[green]Removed:[/green] {rest}" if removed
                          else f"[yellow]No such pattern: {rest}[/yellow]")
            self._show_scope()
        elif sub == "clear":
            n = self.db.clear_scope()
            console.print(f"[green]Cleared {n} scope pattern(s).[/green]")
        elif sub == "on":
            self.scope_enabled = True
            console.print("[green]Scope filtering enabled.[/green]")
            self._show_scope()
        elif sub == "off":
            self.scope_enabled = False
            console.print("[yellow]Scope filtering disabled — showing all captured traffic.[/yellow]")
        elif sub in ("list", ""):
            self._show_scope()
        else:
            # Bare `/scope <pattern>` is treated as a convenient add.
            added = self.db.add_scope(" ".join(args))
            self.scope_enabled = True
            console.print(f"[green]{'Added' if added else 'Already in scope'}:[/green] {' '.join(args)}")
            self._show_scope()

    def _show_scope(self):
        patterns = self.db.list_scope()
        state = "on" if self.scope_enabled else "off"
        if not patterns:
            console.print(f"[dim]Scope is empty (filtering {state}) — all captured "
                          f"requests are shown. Add one with /scope add <pattern>.[/dim]")
            return
        table = Table(title=f"Target scope (filtering {state})", header_style="bold magenta")
        table.add_column("#", justify="right")
        table.add_column("Pattern")
        for i, p in enumerate(patterns, 1):
            table.add_row(str(i), p)
        console.print(table)

    def cmd_select(self, args):
        capture_id = selector.browse_and_select(self.db, self._active_scope())
        if capture_id is None:
            return
        row = self.db.get_captured(capture_id)
        self.current_request = selector.request_from_capture(row)
        console.print(f"[green]Selected capture #{capture_id}: "
                      f"{self.current_request['method']} {self.current_request['url']}[/green]")
        console.print("[dim]Use /mark to wrap fuzz points in §§, then /attack.[/dim]")

    def cmd_mark(self, args):
        if not self.current_request:
            console.print("[yellow]No request selected. Use /select or /paste first.[/yellow]")
            return
        self.current_request = selector.edit_markers(self.current_request)
        n = marker_count(self.current_request)
        console.print(f"[green]{n} marker position(s) found.[/green]")

    # ---------------- attacking ----------------

    def cmd_attack(self, args):
        if not self.current_request:
            console.print("[yellow]No request selected. Use /select or /paste, then /mark.[/yellow]")
            return
        n = marker_count(self.current_request)
        if n == 0:
            console.print("[yellow]No §...§ markers in the current request. Use /mark first.[/yellow]")
            return

        console.print(f"Attack types: {', '.join(ATTACK_TYPES)}")
        attack_type = self.session.prompt("attack type> ").strip() or "sniper"
        if attack_type not in ATTACK_TYPES:
            console.print(f"[red]Unknown attack type '{attack_type}'[/red]")
            return

        n_lists_needed = 1 if attack_type in ("sniper", "battering_ram") else n
        payload_lists = []
        for i in range(n_lists_needed):
            payload_lists.append(self._prompt_payload_list(i, n_lists_needed))

        self._launch_attack(attack_type, payload_lists)

    def _prompt_payload_list(self, index, total):
        import os

        label = f"payload list {index + 1}/{total}" if total > 1 else "payload list"
        source = self.session.prompt(
            f"{label} — file path, 'paste', or paste the list right here> "
        ).strip()

        if not source:
            console.print("[yellow]No payloads given.[/yellow]")
            return []

        # 1) Explicit paste mode: read lines until a blank submission. A
        #    multi-line paste can also arrive as a single submission with
        #    embedded newlines, so split every submission on newlines.
        if source.lower() == "paste":
            console.print("[dim]Paste payloads (one per line). Submit an empty line to finish.[/dim]")
            items = []
            while True:
                line = self.session.prompt("")
                if line == "":
                    break
                items.extend(p for p in line.splitlines() if p.strip() != "")
            if not items:
                console.print("[yellow]That payload list is empty.[/yellow]")
            return items

        # 2) A real file on disk: read one payload per non-blank line.
        if os.path.isfile(source):
            try:
                with open(source, "r", encoding="utf-8", errors="ignore") as f:
                    items = [l.rstrip("\r\n") for l in f if l.strip() != ""]
                if not items:
                    console.print(f"[yellow]{source} contains no payloads.[/yellow]")
                return items
            except OSError as e:
                console.print(f"[red]Could not read {source}: {e}[/red]")
                return []

        # 3) Not 'paste' and not an existing file. If it contains multiple
        #    lines, the user pasted the wordlist straight into this prompt —
        #    treat each line as a payload instead of trying to open it as a
        #    (non-existent) file, which used to silently yield 0 payloads.
        lines = [p for p in source.splitlines() if p.strip() != ""]
        if len(lines) > 1:
            console.print(f"[dim]Read {len(lines)} inline payload(s) from your paste.[/dim]")
            return lines

        # 4) A single token that isn't a file. If it looks like a path they
        #    intended a file that doesn't exist; otherwise treat it as one
        #    literal payload.
        if "/" in source or os.sep in source or source.endswith((".txt", ".lst", ".list")):
            console.print(f"[red]File not found: {source}[/red] "
                          f"(type [bold]paste[/bold] to enter payloads inline instead).")
            return []
        console.print(f"[dim]Using a single literal payload: {source}[/dim]")
        return [source]

    def _launch_attack(self, attack_type, payload_lists):
        # Refuse to "run" an attack that would fire nothing — otherwise the
        # session is created and instantly marked completed with zero results,
        # which looks like a silent failure.
        if not payload_lists or any(len(pl) == 0 for pl in payload_lists):
            console.print("[red]Cannot start: at least one payload list is empty.[/red] "
                          "Re-run [bold]/attack[/bold] and provide payloads "
                          "(a file path, or type [bold]paste[/bold] to enter them inline).")
            return
        try:
            total = total_request_count(self.current_request, attack_type, payload_lists)
        except MarkerError as e:
            console.print(f"[red]{e}[/red]")
            return
        if total == 0:
            console.print("[red]Nothing to attack (0 requests).[/red] Check that the "
                          "request has §…§ markers (/mark) and that your payload lists "
                          "aren't empty.")
            return
        console.print(f"[cyan]{total} request(s) queued for a {attack_type} attack.[/cyan]")

        target_summary = f"{self.current_request['method']} {self.current_request['url']}"
        session_id = self.db.create_session(
            self.current_request, attack_type,
            {"payload_lists": payload_lists}, target_summary
        )
        self.current_session_id = session_id
        self.last_attack_config = (attack_type, payload_lists)

        engine = AttackEngine(self.db, session_id, self.current_request,
                               attack_type, payload_lists)
        self.current_engine = engine
        engine.start()
        self._stream_live(engine, total)

    def _stream_live(self, engine, total):
        console.print(f"[dim]Session {engine.session_id} running — /pause to checkpoint, "
                      f"Ctrl-C-safe (returns to prompt without stopping the attack).[/dim]")
        completed = 0
        try:
            while True:
                item = engine.live_queue.get()
                if item is None:
                    break
                completed += 1
                self._print_live_row(item, completed, total)
        except KeyboardInterrupt:
            console.print("[yellow]Detached from live view (attack keeps running in "
                          "the background). Use /open <session_id> to check back in.[/yellow]")
            return
        console.print(f"[green]Attack finished — {completed} request(s). "
                      f"Use /filter to review, /end to export.[/green]")

    def _print_live_row(self, item, completed, total):
        code = item.get("status_code")
        style = "dim"
        if item.get("timeout"):
            style, label = "magenta", "[TIMEOUT]"
        elif item.get("response_gone"):
            style, label = "red", "[GONE]"
        elif code is not None:
            style = {2: "green", 3: "cyan", 4: "yellow", 5: "red"}.get(code // 100, "white")
            label = str(code)
        else:
            label = item.get("error") or "-"
        console.print(f"[{style}]#{item['request_no']}/{total}  {label}  "
                      f"len={item.get('length')}  {item.get('elapsed_ms', 0):.0f}ms  "
                      f"payloads={item['payloads']}[/{style}]")

    def cmd_pause(self, args):
        if not self.current_engine:
            console.print("[yellow]No active attack.[/yellow]")
            return
        self.current_engine.pause()
        console.print("[yellow]Paused — progress checkpointed.[/yellow]")

    def cmd_resume(self, args):
        if self.current_engine and self.current_engine.is_alive():
            self.current_engine.resume()
            console.print("[green]Resumed.[/green]")
            self._stream_live(self.current_engine, self.current_engine.total)
            return
        if not self.current_session_id:
            console.print("[yellow]No session to resume. Use /open <session_id> first.[/yellow]")
            return
        row = self.db.get_session(self.current_session_id)
        if not row or row["status"] != "paused":
            console.print("[yellow]That session isn't paused.[/yellow]")
            return
        request = json.loads(row["base_request"])
        payload_lists = json.loads(row["payload_config"])["payload_lists"]
        engine = AttackEngine(self.db, row["session_id"], request, row["attack_type"],
                               payload_lists, resume_from=row["last_completed_index"])
        self.current_engine = engine
        engine.start()
        self._stream_live(engine, engine.total)

    def cmd_repeat(self, args):
        if not self.last_attack_config or not self.current_request:
            console.print("[yellow]No previous attack to repeat.[/yellow]")
            return
        attack_type, payload_lists = self.last_attack_config
        self._launch_attack(attack_type, payload_lists)

    def cmd_payload(self, args):
        if not self.last_attack_config:
            console.print("[yellow]No attack configured yet — use /attack first.[/yellow]")
            return
        attack_type, _old_lists = self.last_attack_config
        n = marker_count(self.current_request)
        n_lists_needed = 1 if attack_type in ("sniper", "battering_ram") else n
        payload_lists = [self._prompt_payload_list(i, n_lists_needed) for i in range(n_lists_needed)]
        self.last_attack_config = (attack_type, payload_lists)
        console.print("[green]Payloads updated.[/green] Use /attack or /repeat to run.")

    def cmd_change_method(self, args):
        console.print(f"Attack types: {', '.join(ATTACK_TYPES)}")
        attack_type = self.session.prompt("new attack type> ").strip()
        if attack_type not in ATTACK_TYPES:
            console.print(f"[red]Unknown attack type '{attack_type}'[/red]")
            return
        if self.last_attack_config:
            _, payload_lists = self.last_attack_config
            self.last_attack_config = (attack_type, payload_lists)
        console.print(f"[green]Attack type set to {attack_type}.[/green] Use /attack to (re)run.")

    def cmd_fresh(self, args):
        self.current_request = None
        self.current_session_id = None
        self.current_engine = None
        self.last_attack_config = None
        self.current_sort_col, self.current_sort_desc = "request_no", False
        self.current_keyword, self.current_reverse_kw = None, False
        console.print("[green]State wiped. Start again with /select or /paste.[/green]")

    def cmd_end(self, args):
        if not self.current_session_id:
            console.print("[yellow]No active session.[/yellow]")
            return
        if self.current_engine:
            self.current_engine.stop()
        self.db.update_session_status(self.current_session_id, "completed")
        console.print("[green]Session marked completed.[/green]")
        fmt = self.session.prompt("export format (txt/html/skip)> ").strip().lower() or "skip"
        if fmt in ("txt", "html"):
            self._export(fmt)

    def _export(self, fmt):
        import os
        session = self.db.get_session(self.current_session_id)
        results = self.db.get_results(self.current_session_id, self.current_sort_col,
                                       self.current_sort_desc)
        results = self._apply_keyword(results)
        out_dir = os.environ.get("HYPERNOVA_EXPORT_DIR", os.getcwd())
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError:
            out_dir = os.getcwd()
        path = os.path.join(out_dir, f"hypernova_{self.current_session_id}.{fmt}")
        report.export(session, results, path)
        console.print(f"[green]Exported to {path}[/green]")

    # ---------------- filtering / review ----------------

    def cmd_filter(self, args):
        if args:
            self.current_keyword = args[0]
            self.current_reverse_kw = False
        self._render_results()

    def cmd_filter_ad(self, args):
        self.current_sort_desc = False
        self._render_results()

    def cmd_filter_da(self, args):
        self.current_sort_desc = True
        self._render_results()

    def cmd_filter_rv(self, args):
        if args:
            self.current_keyword = args[0]
            self.current_reverse_kw = True
        self._render_results()

    def _apply_keyword(self, results):
        if not self.current_keyword:
            return results
        kw = self.current_keyword.lower()

        def matches(r):
            hay = f"{r.get('full_request', '')} {r.get('full_response', '')}".lower()
            return kw in hay

        if self.current_reverse_kw:
            return [r for r in results if not matches(r)]
        return [r for r in results if matches(r)]

    def _render_results(self):
        if not self.current_session_id:
            console.print("[yellow]No session loaded. Run /attack or /open <session_id> first.[/yellow]")
            return
        results = self.db.get_results(self.current_session_id, self.current_sort_col,
                                       self.current_sort_desc)
        results = self._apply_keyword(results)
        status_line = (f"sort={self.current_sort_col} "
                       f"{'desc' if self.current_sort_desc else 'asc'}"
                       + (f" | keyword='{self.current_keyword}'"
                          f"{' (reversed)' if self.current_reverse_kw else ''}"
                          if self.current_keyword else ""))
        table = Table(title=f"Session {self.current_session_id} — {status_line}",
                      header_style="bold magenta")
        table.add_column("Req#", justify="right")
        table.add_column("Payloads")
        table.add_column("Status")
        table.add_column("Length", justify="right")
        table.add_column("Time (ms)", justify="right")
        table.add_column("Notes")
        for r in results:
            code = r["status_code"]
            style = "dim"
            if r["timeout"]:
                style, note = "magenta", "TIMEOUT"
            elif r["response_gone"]:
                style, note = "red", "GONE"
            elif code is not None:
                style = {2: "green", 3: "cyan", 4: "yellow", 5: "red"}.get(code // 100, "white")
                note = r["error"] or ""
            else:
                note = r["error"] or ""
            payloads = r["payloads"]
            if isinstance(payloads, str):
                try:
                    payloads = json.loads(payloads)
                except Exception:
                    pass
            table.add_row(
                str(r["request_no"]), str(payloads),
                f"[{style}]{code if code is not None else '-'}[/{style}]",
                str(r["length"]) if r["length"] is not None else "-",
                f"{r['elapsed_ms']:.0f}" if r["elapsed_ms"] else "-",
                note,
            )
        console.print(table)
        console.print("[dim]Row expansion: /open <session_id> then pick a request# "
                      "to see full request/response (see /sessions).[/dim]")

    # ---------------- session review ----------------

    def cmd_sessions(self, args):
        rows = self.db.list_sessions()
        if not rows:
            console.print("[yellow]No sessions yet.[/yellow]")
            return
        table = Table(title="Attack Sessions", header_style="bold magenta")
        table.add_column("Session ID")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Target", overflow="fold")
        table.add_column("Progress", justify="right")
        for r in rows:
            n = self.db.count_results(r["session_id"])
            table.add_row(r["session_id"], r["attack_type"], r["status"],
                          r["target_summary"] or "", str(n))
        console.print(table)

    def cmd_open(self, args):
        if not args:
            console.print("[yellow]Usage: /open <session_id>[/yellow]")
            return
        session_id = args[0]
        row = self.db.get_session(session_id)
        if not row:
            console.print(f"[red]No session {session_id}[/red]")
            return
        self.current_session_id = session_id
        self.current_request = json.loads(row["base_request"])
        self.last_attack_config = (row["attack_type"], json.loads(row["payload_config"])["payload_lists"])
        console.print(f"[green]Opened session {session_id} ({row['status']}).[/green]")
        self._render_results()

        console.print("[dim]Type a request# to expand it inline, or press Enter to skip.[/dim]")
        choice = self.session.prompt("expand> ").strip()
        if choice.isdigit():
            self._expand_row(session_id, int(choice))

    def _expand_row(self, session_id, request_no):
        results = self.db.get_results(session_id)
        match = next((r for r in results if r["request_no"] == request_no), None)
        if not match:
            console.print(f"[red]No request #{request_no} in this session.[/red]")
            return
        console.rule(f"Request #{request_no}")
        console.print(match["full_request"] or "")
        console.rule("Response")
        console.print(match["full_response"] or "")

    # ---------------- exit ----------------

    def _exit(self, args=None):
        console.print("[cyan]Goodbye.[/cyan]")
        if self.capture_proxy:
            self.capture_proxy.stop()
        self.db.close()
        raise SystemExit(0)
