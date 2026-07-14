#!/usr/bin/env python3
"""
web.py - Hypernova's browser-based frontend.

Launched with the ``hypernova-web`` command. It's a thin HTTP/JSON layer over
the *exact same* core the terminal REPL uses — :class:`hypernova.db.DB`, the
:class:`hypernova.engine.AttackEngine`, ``report``, ``scope`` and ``capture``
— so both frontends share one SQLite database and behave identically. The only
thing that differs is the surface:

  * The terminal marks fuzz points by hand-editing raw text in ``$EDITOR``.
  * The web UI lets you *select the value with the mouse and click "Add
    marker"* to wrap the selection in §…§ — no copy/paste round-trip.

Everything else (capture, scope, sniper/pitchfork/battering-ram/clusterbomb,
checkpointed pause/resume, live streaming results, txt/html export) is the same
engine, reached over a small REST API with a Server-Sent-Events stream for the
live result feed.
"""

import json
import os
import threading
import time

try:
    from flask import (Flask, Response, jsonify, request, send_file,
                       stream_with_context)
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

from . import report, scope as scopelib
from .db import DB
from .engine import (AttackEngine, MarkerError, marker_count,
                     total_request_count)

# The single-page frontend lives next to this file as index.html.
_HERE = os.path.dirname(os.path.abspath(__file__))
_INDEX_HTML = os.path.join(_HERE, "webui", "index.html")

ATTACK_TYPES = ["sniper", "pitchfork", "battering_ram", "clusterbomb"]


# --------------------------------------------------------------------------- #
#  request-text parsing (shared shape with the REPL's parser)
# --------------------------------------------------------------------------- #

def parse_raw_request(raw: str) -> dict:
    """Parse a raw HTTP request (method+URL line, headers, blank line, body)
    into the engine's {method,url,headers,body} dict. §…§ markers, being
    ordinary characters, pass straight through untouched."""
    raw = (raw or "").replace("\r\n", "\n")
    lines = raw.split("\n")
    first = lines[0].split(" ") if lines else []
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


def request_to_raw(req: dict) -> str:
    """Inverse of parse_raw_request: render a request dict as editable raw
    text so the browser can show it, let the user select-and-mark, and send it
    back."""
    lines = [f"{req.get('method', 'GET')} {req.get('url', '')}"]
    for k, v in (req.get("headers") or {}).items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(req.get("body") or "")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  app factory
# --------------------------------------------------------------------------- #

def create_app(db_path=None):
    if not FLASK_AVAILABLE:
        raise RuntimeError(
            "Flask is not installed (the web frontend's only extra dependency).\n"
            "Install it with:  pipx inject hypernova flask\n"
            "  (or, inside a venv:  pip install 'hypernova[web]')\n"
            "The terminal frontend `hypernova` needs no extra dependencies.")

    app = Flask(__name__)
    db = DB(db_path) if db_path else DB()

    # Shared mutable state, guarded where it matters. One capture proxy and a
    # registry of live attack engines keyed by session_id — same lifetimes the
    # REPL keeps, just reachable over HTTP.
    state = {
        "capture_proxy": None,
        "scope_enabled": True,
        "engines": {},          # session_id -> AttackEngine
    }
    lock = threading.Lock()

    def active_scope():
        if not state["scope_enabled"]:
            return None
        patterns = db.list_scope()
        return patterns or None

    def scope_filter(rows):
        patterns = active_scope()
        if not patterns:
            return rows
        return [r for r in rows if scopelib.in_scope(r["url"], patterns)]

    # ----------------------------- pages ----------------------------------- #

    @app.route("/")
    def index():
        return send_file(_INDEX_HTML)

    # --------------------------- captures ---------------------------------- #

    @app.route("/api/captures")
    def api_captures():
        kw = request.args.get("q", "").strip()
        rows = db.search_captured(kw) if kw else db.list_captured()
        return jsonify(scope_filter(rows))

    @app.route("/api/captures/<int:capture_id>")
    def api_capture_detail(capture_id):
        row = db.get_captured(capture_id)
        if not row:
            return jsonify({"error": f"No capture #{capture_id}"}), 404
        headers = json.loads(row.get("headers") or "{}")
        resp_headers = json.loads(row.get("response_headers") or "{}")
        req = {
            "method": row["method"], "url": row["url"],
            "headers": headers, "body": row.get("body") or "",
        }
        return jsonify({
            "capture": {
                "id": row["id"],
                "method": row["method"],
                "url": row["url"],
                "headers": headers,
                "body": row.get("body") or "",
                "response_status": row.get("response_status"),
                "response_headers": resp_headers,
                "response_body": row.get("response_body") or "",
            },
            # The editable raw form used by the marker editor.
            "raw": request_to_raw(req),
        })

    @app.route("/api/paste", methods=["POST"])
    def api_paste():
        raw = (request.get_json(force=True) or {}).get("raw", "")
        if not raw.strip():
            return jsonify({"error": "Empty request."}), 400
        parsed = parse_raw_request(raw)
        capture_id = db.insert_captured(
            parsed["method"], parsed["url"], parsed["headers"], parsed["body"])
        return jsonify({"capture_id": capture_id, **parsed})

    # ---------------------------- scope ------------------------------------ #

    @app.route("/api/scope", methods=["GET"])
    def api_scope_get():
        return jsonify({
            "patterns": db.list_scope(),
            "enabled": state["scope_enabled"],
        })

    @app.route("/api/scope", methods=["POST"])
    def api_scope_post():
        body = request.get_json(force=True) or {}
        action = body.get("action")
        pattern = (body.get("pattern") or "").strip()
        if action == "add" and pattern:
            db.add_scope(pattern)
            state["scope_enabled"] = True
        elif action == "rm" and pattern:
            db.remove_scope(pattern)
        elif action == "clear":
            db.clear_scope()
        elif action == "on":
            state["scope_enabled"] = True
        elif action == "off":
            state["scope_enabled"] = False
        else:
            return jsonify({"error": "Unknown scope action."}), 400
        return jsonify({
            "patterns": db.list_scope(),
            "enabled": state["scope_enabled"],
        })

    # --------------------------- marking ----------------------------------- #

    @app.route("/api/markers", methods=["POST"])
    def api_markers():
        """Count markers in a raw request — used to validate before /attack and
        to show the live §×N badge as the user marks up the request."""
        raw = (request.get_json(force=True) or {}).get("raw", "")
        req = parse_raw_request(raw)
        try:
            n = marker_count(req)
        except Exception:
            n = 0
        return jsonify({"markers": n})

    # --------------------------- attacking --------------------------------- #

    @app.route("/api/attack", methods=["POST"])
    def api_attack():
        body = request.get_json(force=True) or {}
        raw = body.get("raw", "")
        attack_type = body.get("attack_type", "sniper")
        payload_lists = body.get("payload_lists") or []

        if attack_type not in ATTACK_TYPES:
            return jsonify({"error": f"Unknown attack type '{attack_type}'."}), 400

        req = parse_raw_request(raw)
        n = marker_count(req)
        if n == 0:
            return jsonify({"error": "No §…§ markers. Select a value and click "
                                     "“Add marker” first."}), 400

        # Normalize payload lists: drop blank lines, drop empty lists.
        cleaned = []
        for pl in payload_lists:
            if isinstance(pl, str):
                pl = pl.splitlines()
            cleaned.append([p for p in pl if str(p).strip() != ""])

        need = 1 if attack_type in ("sniper", "battering_ram") else n
        if len(cleaned) < need:
            return jsonify({"error": f"{attack_type} needs {need} payload "
                                     f"list(s); got {len(cleaned)}."}), 400
        cleaned = cleaned[:need]
        if any(len(pl) == 0 for pl in cleaned):
            return jsonify({"error": "At least one payload list is empty."}), 400

        try:
            total = total_request_count(req, attack_type, cleaned)
        except MarkerError as e:
            return jsonify({"error": str(e)}), 400
        if total == 0:
            return jsonify({"error": "Nothing to attack (0 requests)."}), 400

        target_summary = f"{req['method']} {req['url']}"
        session_id = db.create_session(req, attack_type,
                                       {"payload_lists": cleaned}, target_summary)
        engine = AttackEngine(db, session_id, req, attack_type, cleaned)
        with lock:
            state["engines"][session_id] = engine
        engine.start()
        return jsonify({"session_id": session_id, "total": total,
                        "attack_type": attack_type})

    @app.route("/api/sessions/<session_id>/pause", methods=["POST"])
    def api_pause(session_id):
        engine = state["engines"].get(session_id)
        if engine and engine.is_alive():
            engine.pause()
            return jsonify({"status": "paused"})
        return jsonify({"error": "No running attack for that session."}), 400

    @app.route("/api/sessions/<session_id>/resume", methods=["POST"])
    def api_resume(session_id):
        engine = state["engines"].get(session_id)
        if engine and engine.is_alive():
            engine.resume()
            return jsonify({"status": "running"})
        # Resume a paused session that has no live engine (e.g. after a restart).
        row = db.get_session(session_id)
        if not row or row["status"] != "paused":
            return jsonify({"error": "That session isn't paused."}), 400
        req = json.loads(row["base_request"])
        payload_lists = json.loads(row["payload_config"])["payload_lists"]
        engine = AttackEngine(db, session_id, req, row["attack_type"],
                              payload_lists, resume_from=row["last_completed_index"])
        with lock:
            state["engines"][session_id] = engine
        engine.start()
        return jsonify({"status": "running"})

    @app.route("/api/sessions/<session_id>/stop", methods=["POST"])
    def api_stop(session_id):
        engine = state["engines"].get(session_id)
        if engine:
            engine.stop()
        db.update_session_status(session_id, "completed")
        return jsonify({"status": "completed"})

    # ------------------------- live result stream -------------------------- #

    @app.route("/api/sessions/<session_id>/stream")
    def api_stream(session_id):
        """Server-Sent-Events feed of results as they land. Polls the DB (not
        the engine's in-memory queue) so a browser refresh or a second tab
        re-attaches cleanly and never loses or double-counts a row."""
        total = 0
        row = db.get_session(session_id)
        if row:
            try:
                payload_lists = json.loads(row["payload_config"])["payload_lists"]
                total = total_request_count(json.loads(row["base_request"]),
                                            row["attack_type"], payload_lists)
            except Exception:
                total = 0

        @stream_with_context
        def gen():
            seen = set()
            yield f"event: meta\ndata: {json.dumps({'total': total})}\n\n"
            while True:
                results = db.get_results(session_id)
                for r in results:
                    if r["request_no"] in seen:
                        continue
                    seen.add(r["request_no"])
                    payloads = r["payloads"]
                    if isinstance(payloads, str):
                        try:
                            payloads = json.loads(payloads)
                        except Exception:
                            pass
                    yield "event: result\ndata: " + json.dumps({
                        "request_no": r["request_no"],
                        "payloads": payloads,
                        "status_code": r["status_code"],
                        "length": r["length"],
                        "elapsed_ms": r["elapsed_ms"],
                        "timeout": bool(r["timeout"]),
                        "response_gone": bool(r["response_gone"]),
                        "error": r["error"],
                    }) + "\n\n"

                sess = db.get_session(session_id)
                status = sess["status"] if sess else "completed"
                done = len(seen) >= total and total > 0
                if status in ("completed",) or (status == "paused"):
                    # Flush any final rows already emitted above, then close.
                    yield ("event: done\ndata: "
                           + json.dumps({"status": status, "count": len(seen)})
                           + "\n\n")
                    return
                if done:
                    yield ("event: done\ndata: "
                           + json.dumps({"status": "completed", "count": len(seen)})
                           + "\n\n")
                    return
                time.sleep(0.4)

        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    # --------------------------- sessions ---------------------------------- #

    @app.route("/api/sessions")
    def api_sessions():
        rows = db.list_sessions()
        for r in rows:
            r["count"] = db.count_results(r["session_id"])
        return jsonify(rows)

    @app.route("/api/sessions/<session_id>")
    def api_session_results(session_id):
        row = db.get_session(session_id)
        if not row:
            return jsonify({"error": f"No session {session_id}"}), 404
        sort = request.args.get("sort", "request_no")
        desc = request.args.get("desc", "false").lower() == "true"
        keyword = request.args.get("keyword", "").strip()
        reverse = request.args.get("reverse", "false").lower() == "true"

        results = db.get_results(session_id, sort, desc)
        if keyword:
            kw = keyword.lower()

            def matches(r):
                hay = f"{r.get('full_request','')} {r.get('full_response','')}".lower()
                return kw in hay
            results = [r for r in results if (matches(r) != reverse)]

        out = []
        for r in results:
            payloads = r["payloads"]
            if isinstance(payloads, str):
                try:
                    payloads = json.loads(payloads)
                except Exception:
                    pass
            out.append({
                "request_no": r["request_no"], "payloads": payloads,
                "status_code": r["status_code"], "length": r["length"],
                "elapsed_ms": r["elapsed_ms"], "timeout": bool(r["timeout"]),
                "response_gone": bool(r["response_gone"]), "error": r["error"],
            })
        engine = state["engines"].get(session_id)
        return jsonify({
            "session_id": session_id,
            "attack_type": row["attack_type"],
            "status": row["status"],
            "target_summary": row.get("target_summary", ""),
            "running": bool(engine and engine.is_alive()),
            "results": out,
        })

    @app.route("/api/sessions/<session_id>/results/<int:request_no>")
    def api_result_detail(session_id, request_no):
        results = db.get_results(session_id)
        match = next((r for r in results if r["request_no"] == request_no), None)
        if not match:
            return jsonify({"error": f"No request #{request_no}"}), 404
        return jsonify({
            "request_no": request_no,
            "full_request": match["full_request"] or "",
            "full_response": match["full_response"] or "",
        })

    @app.route("/api/sessions/<session_id>/export")
    def api_export(session_id):
        fmt = request.args.get("fmt", "html").lower()
        if fmt not in ("html", "txt"):
            fmt = "html"
        session = db.get_session(session_id)
        if not session:
            return jsonify({"error": f"No session {session_id}"}), 404
        results = db.get_results(session_id)
        # report.export writes to a path; render it, then stream it back as a
        # download (and leave the file in cwd, mirroring the terminal /end flow).
        out_dir = os.environ.get("HYPERNOVA_EXPORT_DIR", os.getcwd())
        path = os.path.join(out_dir, f"hypernova_{session_id}.{fmt}")
        report.export(session, results, path)
        return send_file(path, as_attachment=True,
                         download_name=f"hypernova_{session_id}.{fmt}")

    # --------------------------- capture proxy ----------------------------- #

    @app.route("/api/capture/status")
    def api_capture_status():
        from . import capture as capmod
        proxy = state["capture_proxy"]
        running = bool(proxy and getattr(proxy, "running", False))
        return jsonify({
            "available": capmod.MITMPROXY_AVAILABLE,
            "running": running,
            "port": proxy.port if running else None,
            "count": proxy.captured_count if running else 0,
            "last_url": proxy.last_url if running else None,
        })

    @app.route("/api/capture/start", methods=["POST"])
    def api_capture_start():
        from . import capture as capmod
        if not capmod.MITMPROXY_AVAILABLE:
            return jsonify({"error": "mitmproxy is not installed. Install it with "
                                     "'pipx inject hypernova mitmproxy', or use "
                                     "Paste to load a request by hand."}), 400
        proxy = state["capture_proxy"]
        if proxy and proxy.running:
            return jsonify({"error": f"Capture already running on port {proxy.port}."}), 400
        try:
            port = int((request.get_json(force=True) or {}).get("port", 8090))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid port."}), 400
        proxy = capmod.CaptureProxy(db, port=port)
        proxy.start()
        if proxy.startup_error:
            return jsonify({"error": proxy.startup_error}), 400
        state["capture_proxy"] = proxy
        return jsonify({"running": True, "port": port})

    @app.route("/api/capture/stop", methods=["POST"])
    def api_capture_stop():
        proxy = state["capture_proxy"]
        if not proxy or not proxy.running:
            return jsonify({"error": "No capture proxy running."}), 400
        n = proxy.captured_count
        proxy.stop()
        state["capture_proxy"] = None
        return jsonify({"stopped": True, "count": n})

    return app


# --------------------------------------------------------------------------- #
#  entry point
# --------------------------------------------------------------------------- #

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="hypernova-web",
        description="Browser-based frontend for the Hypernova HTTP intruder")
    parser.add_argument("--db", help="Path to the SQLite database file "
                                     "(default: ~/.hypernova/hypernova.db) — "
                                     "shared with the terminal `hypernova`.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Interface to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8099,
                        help="Port to serve the UI on (default 8099)")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't auto-open a browser tab")
    args = parser.parse_args()

    if not FLASK_AVAILABLE:
        print("Flask is not installed — the web frontend needs it.\n"
              "  pipx inject hypernova flask        (if installed via pipx)\n"
              "  pip install 'hypernova[web]'        (inside a venv)\n"
              "The terminal frontend `hypernova` works without it.")
        raise SystemExit(1)

    app = create_app(db_path=args.db)
    url = f"http://{args.host}:{args.port}"
    print(f"\n  H Y P E R N O V A  —  web frontend")
    print(f"  Serving on {url}   (Ctrl-C to stop)")
    print(f"  Sharing the same database as the `hypernova` terminal app.\n")

    if not args.no_browser:
        def _open():
            time.sleep(1.0)
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    # threaded=True so the SSE stream endpoint doesn't block other requests.
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
