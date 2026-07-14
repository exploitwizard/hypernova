"""
capture.py - MITM proxy layer, built on mitmproxy.

Point FoxyProxy (or any browser proxy setting) at 127.0.0.1:<port> and every
request/response pair that passes through lands in the SQLite
`captured_traffic` table automatically, no manual export needed.

mitmproxy is a heavy dependency (its own asyncio event loop, addon system),
so this module is isolated and only imported when `/capture start` is
actually run — the rest of Hypernova (engine, REPL, sessions) works fine
without it, e.g. against manually pasted requests.

Install with:  pip install mitmproxy
CA cert setup: run once, then visit http://mitm.it in the proxied browser
               to install Hypernova's CA cert (identical flow to Burp).
"""

import logging
import threading

try:
    from mitmproxy import http
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    import asyncio
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False


class _StartupErrorHandler(logging.Handler):
    """mitmproxy's own ErrorCheck addon swallows the real reason for a
    startup failure and only prints a generic 'Error logged during startup,
    exiting...' message. We attach our own handler to the root logger so we
    can capture the actual ERROR-level record(s) and surface them instead."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.records = []

    def emit(self, record):
        self.records.append(self.format(record))


class CaptureAddon:
    """mitmproxy addon: on every completed flow, write it into the DB.

    Keeps a running ``count`` of stored flows so the REPL can show live
    "captured N request(s)" feedback in its status bar. Any error while
    storing a single flow is swallowed (and counted) rather than allowed to
    bubble up and tear down the proxy — one malformed request must never stop
    the whole capture session."""

    def __init__(self, db):
        self.db = db
        self.count = 0
        self.errors = 0
        self.last_url = None

    def response(self, flow: "http.HTTPFlow") -> None:  # noqa: F821
        req = flow.request
        resp = flow.response
        try:
            headers = dict(req.headers)
            resp_headers = dict(resp.headers) if resp else {}
            try:
                body = req.get_text(strict=False) or ""
            except Exception:
                body = ""
            try:
                resp_body = resp.get_text(strict=False) if resp else ""
            except Exception:
                resp_body = ""
            self.db.insert_captured(
                method=req.method,
                url=req.pretty_url,
                headers=headers,
                body=body,
                response_status=resp.status_code if resp else None,
                response_body=resp_body,
                response_headers=resp_headers,
            )
            self.count += 1
            self.last_url = f"{req.method} {req.pretty_url}"
        except Exception:
            # Never let one bad flow kill the capture loop.
            self.errors += 1


class CaptureProxy:
    """Runs mitmproxy's DumpMaster in a background thread with its own
    asyncio event loop, so it doesn't block the REPL's prompt_toolkit loop."""

    def __init__(self, db, port=8090):
        if not MITMPROXY_AVAILABLE:
            raise RuntimeError(
                "mitmproxy is not installed. Run: pip install mitmproxy\n"
                "Capture is optional — you can still build attacks from "
                "manually pasted requests via /paste."
            )
        self.db = db
        self.port = port
        self.master = None
        self.addon = CaptureAddon(db)
        self._thread = None
        self._loop = None
        self.startup_error = None
        self.running = False
        self._started_event = threading.Event()

    @property
    def captured_count(self):
        return self.addon.count

    @property
    def last_url(self):
        return self.addon.last_url

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # Give startup (cert generation, socket bind, addon init) a moment
        # to fail fast so callers can report a real error instead of a
        # false "proxy running" message.
        self._started_event.wait(timeout=4)
        self.running = self.startup_error is None

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        handler = _StartupErrorHandler()
        logging.getLogger().addHandler(handler)
        try:
            self._loop.run_until_complete(self._main())
        except (Exception, SystemExit) as e:
            # NOTE: SystemExit raised by mitmproxy's ErrorCheck addon (via a
            # Task callback) propagates straight out of run_until_complete,
            # bypassing any try/except *inside* _main()'s own coroutine —
            # this is why we catch it here, at the outer level, instead.
            if not self.startup_error:
                code = getattr(e, "code", None)
                raw = (
                    "\n".join(handler.records) if handler.records
                    else (str(e) if str(e) else f"mitmproxy exited during startup (code {code})")
                )
                self.startup_error = self._clean_error(raw)
        finally:
            logging.getLogger().removeHandler(handler)
            self._started_event.set()

    async def _main(self):
        opts = Options(listen_host="127.0.0.1", listen_port=self.port)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(self.addon)
        run_task = asyncio.ensure_future(self.master.run())
        # errorcheck (bad cert dir, port in use, etc.) fails within the
        # first moment of startup; if run() hasn't returned by then, we
        # take it as successfully listening and let the REPL proceed.
        done, _pending = await asyncio.wait({run_task}, timeout=1.5)
        if run_task in done:
            exc = run_task.exception()
            if exc:
                raise exc
            return
        self._started_event.set()
        await run_task

    def _clean_error(self, raw: str) -> str:
        """Turn mitmproxy's verbose startup log into a short, actionable line."""
        low = raw.lower()
        if "address already in use" in low or "errno 48" in low:
            return (f"port {self.port} is already in use. "
                    f"Try a different port:  /capture {self.port + 1}")
        # Drop mitmproxy's internal "--mode regular@..." hint, which doesn't
        # apply to how Hypernova drives it.
        for line in raw.splitlines():
            if "--mode" in line:
                continue
            line = line.strip()
            if line:
                return line
        return raw.strip()

    def stop(self):
        self.running = False
        if self.master and self._loop:
            self._loop.call_soon_threadsafe(self.master.shutdown)

    @property
    def cert_hint(self):
        return ("Proxy running on 127.0.0.1:%d — point FoxyProxy at it, then "
                "visit http://mitm.it in the proxied browser to install "
                "Hypernova's CA certificate." % self.port)
