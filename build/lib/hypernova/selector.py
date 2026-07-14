"""
selector.py - Browse captured traffic and pick/mark a request to attack.

Uses `rich` for a colored table of captured requests and a simple
search-as-you-type filter (via prompt_toolkit) so you can narrow hundreds
of captured requests down by typing part of a URL.
"""

import json
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qsl

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from prompt_toolkit import prompt

from . import scope as scopelib

console = Console()

STATUS_STYLE = {
    2: "green", 3: "cyan", 4: "yellow", 5: "red",
}

# Response bodies can be megabytes; only render the head in the detail view.
_BODY_PREVIEW_LIMIT = 4000


def _status_style(code):
    if code is None:
        return "dim"
    return STATUS_STYLE.get(code // 100, "white")


def _fmt_time(ts):
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    except Exception:
        return ""


def _split_url(url):
    """Return (host, path-with-query) for the compact history columns."""
    try:
        p = urlparse(url)
        host = p.netloc or url
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return host, path
    except Exception:
        return url, ""


def render_history_table(rows, title="Proxy HTTP history"):
    """Burp-style history grid: one row per captured request/response."""
    table = Table(title=title, header_style="bold magenta", expand=True)
    table.add_column("ID", justify="right", no_wrap=True)
    table.add_column("Method", no_wrap=True)
    table.add_column("Host", overflow="fold")
    table.add_column("Path", overflow="fold", ratio=2)
    table.add_column("Status", justify="right", no_wrap=True)
    table.add_column("Len", justify="right", no_wrap=True)
    table.add_column("Time", justify="right", no_wrap=True)
    for r in rows:
        status = r.get("response_status")
        host, path = _split_url(r["url"])
        length = r.get("length")
        table.add_row(
            str(r["id"]), r["method"], host, path,
            f"[{_status_style(status)}]{status if status is not None else '-'}[/]",
            str(length) if length is not None else "-",
            _fmt_time(r.get("timestamp")),
        )
    console.print(table)


# Kept for backwards-compat with any callers expecting the old name.
render_capture_table = render_history_table


def _kv_table(title, items):
    """Small two-column key/value grid (headers, params, …)."""
    table = Table(title=title, header_style="bold cyan", show_edge=True,
                  title_justify="left", expand=True)
    table.add_column("Name", style="bold", overflow="fold", no_wrap=False)
    table.add_column("Value", overflow="fold", ratio=3)
    for k, v in items:
        table.add_row(str(k), str(v))
    return table


def show_capture_detail(db, capture_id):
    """Expand a single captured request the way Burp's message editor does:
    the raw request line + every header, the parsed query/body parameters,
    then the full response (status line, headers, body preview)."""
    row = db.get_captured(capture_id)
    if not row:
        console.print(f"[red]No capture with id {capture_id}[/red]")
        return

    headers = json.loads(row.get("headers") or "{}")
    resp_headers = json.loads(row.get("response_headers") or "{}")
    url = row["url"]
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # ---- request ----
    console.rule(f"[bold]Request #{capture_id}[/bold]  {row['method']} {url}")
    req_lines = [f"[bold green]{row['method']}[/bold green] {path} HTTP/1.1"]
    for k, v in headers.items():
        req_lines.append(f"[cyan]{k}[/cyan]: {v}")
    console.print(Panel("\n".join(req_lines), title="Request headers",
                        title_align="left", border_style="green"))

    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    if query_params:
        console.print(_kv_table("Query parameters", query_params))

    body = row.get("body") or ""
    if body:
        body_params = []
        ctype = str(headers.get("Content-Type", headers.get("content-type", ""))).lower()
        if "application/x-www-form-urlencoded" in ctype or ("=" in body and "&" in body and "\n" not in body.strip()):
            body_params = parse_qsl(body, keep_blank_values=True)
        if body_params:
            console.print(_kv_table("Body parameters", body_params))
        console.print(Panel(body[:_BODY_PREVIEW_LIMIT]
                            + ("\n[dim]… (truncated)[/dim]" if len(body) > _BODY_PREVIEW_LIMIT else ""),
                            title="Request body", title_align="left", border_style="dim"))

    # ---- response ----
    status = row.get("response_status")
    resp_body = row.get("response_body") or ""
    console.rule(f"[bold]Response[/bold]  "
                 f"[{_status_style(status)}]{status if status is not None else 'no response'}[/]")
    if resp_headers:
        resp_lines = [f"[cyan]{k}[/cyan]: {v}" for k, v in resp_headers.items()]
        console.print(Panel("\n".join(resp_lines), title="Response headers",
                            title_align="left", border_style="magenta"))
    if resp_body:
        console.print(Panel(resp_body[:_BODY_PREVIEW_LIMIT]
                            + ("\n[dim]… (truncated)[/dim]" if len(resp_body) > _BODY_PREVIEW_LIMIT else ""),
                            title="Response body", title_align="left", border_style="dim"))
    console.rule()


def _scope_filter(rows, scope_patterns):
    if not scope_patterns:
        return rows
    return [r for r in rows if scopelib.in_scope(r["url"], scope_patterns)]


def browse_history(db, scope_patterns=None):
    """Interactive Burp-like HTTP history viewer. Lists captured traffic
    (optionally scope-filtered), lets you expand any row to see full
    headers/params/values, keyword-filter, or pick one to attack.

    Returns a capture_id if the user chose one to send to the attack flow,
    else None."""
    rows = _scope_filter(db.list_captured(), scope_patterns)
    if not rows:
        if scope_patterns:
            console.print("[yellow]No captured requests are in scope yet. "
                          "Adjust /scope or browse the target.[/yellow]")
        else:
            console.print("[yellow]No captured traffic yet. Start /capture or /paste a request.[/yellow]")
        return None

    scope_note = f" [dim](scope: {', '.join(scope_patterns)})[/dim]" if scope_patterns else ""
    render_history_table(rows, title=f"Proxy HTTP history — {len(rows)} request(s){scope_note}")
    console.print("[dim]Commands: [bold]<id>[/bold] expand full request/response · "
                  "[bold]/<keyword>[/bold] filter · [bold]use <id>[/bold] send to /attack · "
                  "[bold]all[/bold] show unfiltered · Enter to exit.[/dim]")

    current = rows
    while True:
        query = prompt("history> ").strip()
        if not query:
            return None
        if query.lower() == "all":
            current = db.list_captured()
            render_history_table(current, title=f"Proxy HTTP history — {len(current)} request(s) (unfiltered)")
            continue
        if query.lower().startswith("use "):
            rest = query[4:].strip()
            if rest.isdigit() and db.get_captured(int(rest)):
                return int(rest)
            console.print(f"[red]No capture with id {rest}[/red]")
            continue
        if query.startswith("/"):
            kw = query[1:].strip()
            current = _scope_filter(db.search_captured(kw), scope_patterns)
            if not current:
                console.print("[yellow]No matches.[/yellow]")
                continue
            render_history_table(current, title=f"Matches for '{kw}' — {len(current)} request(s)")
            continue
        if query.isdigit():
            show_capture_detail(db, int(query))
            continue
        console.print("[yellow]Type an ID, /keyword, 'use <id>', 'all', or Enter to exit.[/yellow]")


def browse_and_select(db, scope_patterns=None):
    """Interactive loop: show captured traffic, allow live keyword narrowing
    and inline expansion, return the chosen capture_id or None.

    Scope-aware: when scope_patterns is set, only in-scope requests are shown
    (an ID outside scope can still be selected explicitly)."""
    rows = _scope_filter(db.list_captured(), scope_patterns)
    if not rows:
        if scope_patterns:
            console.print("[yellow]No in-scope captured traffic. Adjust /scope, "
                          "or /capture / /paste a request.[/yellow]")
        else:
            console.print("[yellow]No captured traffic yet. Start /capture or /paste a request.[/yellow]")
        return None

    render_history_table(rows)
    console.print("[dim]Type an [bold]ID[/bold] to select it, [bold]?<id>[/bold] to preview it "
                  "first, part of a URL to narrow, or leave blank to cancel.[/dim]")
    while True:
        query = prompt("selector> ").strip()
        if not query:
            return None
        if query.startswith("?") and query[1:].strip().isdigit():
            show_capture_detail(db, int(query[1:].strip()))
            continue
        if query.isdigit():
            capture_id = int(query)
            if db.get_captured(capture_id):
                return capture_id
            console.print(f"[red]No capture with id {capture_id}[/red]")
            continue
        matches = _scope_filter(db.search_captured(query), scope_patterns)
        if not matches:
            console.print("[yellow]No matches. Try another keyword.[/yellow]")
            continue
        render_history_table(matches, title=f"Matches for '{query}'")


def request_from_capture(row: dict) -> dict:
    """Convert a captured_traffic DB row into the engine's request dict
    shape: {method, url, headers, body}."""
    import json
    headers = json.loads(row.get("headers") or "{}")
    return {
        "method": row["method"],
        "url": row["url"],
        "headers": headers,
        "body": row.get("body") or "",
    }


def edit_markers(request: dict) -> dict:
    """Drop into an editable view of method/url/headers/body so the user can
    manually wrap insertion points in §...§. Uses $EDITOR if set, otherwise a
    simple inline prompt_toolkit multi-line editor."""
    import os
    import tempfile
    import subprocess

    raw = (
        f"{request['method']} {request['url']}\n"
        + "\n".join(f"{k}: {v}" for k, v in request.get("headers", {}).items())
        + "\n\n" + (request.get("body") or "")
    )

    editor = os.environ.get("EDITOR")
    if editor:
        with tempfile.NamedTemporaryFile("w+", suffix=".http", delete=False) as f:
            f.write(raw)
            path = f.name
        subprocess.call([editor, path])
        with open(path) as f:
            raw = f.read()
        os.unlink(path)
    else:
        console.print("[dim]No $EDITOR set — inline editor. Wrap values you want "
                      "to fuzz in §like this§. Submit with an empty line.[/dim]")
        console.print(raw)
        lines = []
        console.print("[dim]Paste the full edited request, end with a blank line:[/dim]")
        while True:
            line = prompt("")
            if line == "":
                break
            lines.append(line)
        if lines:
            raw = "\n".join(lines)

    # Re-parse raw back into method/url/headers/body
    lines = raw.split("\n")
    first = lines[0].split(" ")
    method = first[0] if first else request["method"]
    if len(first) >= 3 and first[-1].upper().startswith("HTTP/"):
        url = " ".join(first[1:-1])
    elif len(first) >= 2:
        url = " ".join(first[1:])
    else:
        url = request["url"]
    headers = {}
    i = 1
    while i < len(lines) and lines[i].strip() != "":
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i + 1:]) if i + 1 < len(lines) else ""
    return {"method": method, "url": url, "headers": headers, "body": body}
