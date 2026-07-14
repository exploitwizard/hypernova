"""
engine.py - The Hypernova attack engine.

Reuses PyIntruder-style attack-mode logic (sniper / pitchfork / battering-ram /
clusterbomb) against a request template marked up with §...§ position markers,
adds SQLite-backed result storage, batched checkpointing for pause/resume, and
a live result queue the REPL can stream from.
"""

import re
import time
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from itertools import product
import requests

MARKER_RE = re.compile(r"§(.*?)§", re.DOTALL)
CHECKPOINT_BATCH = 10  # persist last_completed_index every N completed requests


class MarkerError(Exception):
    pass


def _combine_request(request: dict) -> str:
    """Flatten method/url/headers/body into one string so markers can be
    found and substituted with a single, order-preserving pass."""
    parts = [request.get("method", "GET"), request.get("url", "")]
    for k, v in (request.get("headers") or {}).items():
        parts.append(f"{k}: {v}")
    parts.append(request.get("body") or "")
    return "\x00".join(parts)


def _split_combined(combined: str, n_headers: int):
    parts = combined.split("\x00")
    method, url = parts[0], parts[1]
    header_lines = parts[2:2 + n_headers]
    body = "\x00".join(parts[2 + n_headers:])  # in case body itself had \x00 (unlikely)
    headers = {}
    for line in header_lines:
        if ":" in line:
            name, _, val = line.partition(":")
            headers[name.strip()] = val.strip()
    return {"method": method, "url": url, "headers": headers, "body": body}


def find_markers(request: dict):
    """Return (combined_string, list of (start, end, base_value) marker spans,
    n_headers) — used both for validation and generation."""
    combined = _combine_request(request)
    spans = [(m.start(), m.end(), m.group(1)) for m in MARKER_RE.finditer(combined)]
    n_headers = len(request.get("headers") or {})
    if len(spans) % 2 != 0 and False:
        pass  # regex already pairs §...§ correctly; kept for clarity
    return combined, spans, n_headers


def marker_count(request: dict) -> int:
    _, spans, _ = find_markers(request)
    return len(spans)


def _render(combined: str, spans, values):
    """Replace each marked span (including its § § delimiters) with the given
    value, working from the end of the string backwards so earlier offsets
    stay valid."""
    out = combined
    # spans are (start_of_§, end_of_closing_§, base_value) in ascending order
    for (start, end, _base), value in zip(reversed(spans), reversed(values)):
        out = out[:start] + str(value) + out[end:]
    return out


def build_requests(request: dict, attack_type: str, payload_lists):
    """
    Generator yielding (request_no, payload_values, rendered_request_dict).

    payload_lists: list of lists. For sniper/battering-ram, a single list
    (index 0) is used. For pitchfork/clusterbomb, one list per marked
    position is expected (order matches marker order left-to-right).
    """
    combined, spans, n_headers = find_markers(request)
    n_positions = len(spans)
    if n_positions == 0:
        raise MarkerError("No §...§ markers found in the request. Mark at "
                           "least one insertion point before attacking.")

    base_values = [s[2] for s in spans]

    if attack_type == "sniper":
        payloads = payload_lists[0]
        req_no = 0
        for pos in range(n_positions):
            for p in payloads:
                values = list(base_values)
                values[pos] = p
                req_no += 1
                yield req_no, [p], _split_combined(_render(combined, spans, values), n_headers)

    elif attack_type == "battering_ram":
        payloads = payload_lists[0]
        req_no = 0
        for p in payloads:
            values = [p] * n_positions
            req_no += 1
            yield req_no, [p] * n_positions, _split_combined(_render(combined, spans, values), n_headers)

    elif attack_type == "pitchfork":
        if len(payload_lists) < n_positions:
            raise MarkerError(f"pitchfork needs one payload list per position "
                               f"({n_positions} positions, {len(payload_lists)} lists given)")
        length = min(len(lst) for lst in payload_lists[:n_positions])
        req_no = 0
        for i in range(length):
            values = [payload_lists[pos][i] for pos in range(n_positions)]
            req_no += 1
            yield req_no, list(values), _split_combined(_render(combined, spans, values), n_headers)

    elif attack_type == "clusterbomb":
        if len(payload_lists) < n_positions:
            raise MarkerError(f"clusterbomb needs one payload list per position "
                               f"({n_positions} positions, {len(payload_lists)} lists given)")
        lists = payload_lists[:n_positions]
        req_no = 0
        for combo in product(*lists):
            req_no += 1
            yield req_no, list(combo), _split_combined(_render(combined, spans, combo), n_headers)

    else:
        raise MarkerError(f"Unknown attack type: {attack_type}")


def total_request_count(request: dict, attack_type: str, payload_lists) -> int:
    n_positions = marker_count(request)
    if attack_type == "sniper":
        return n_positions * len(payload_lists[0])
    if attack_type == "battering_ram":
        return len(payload_lists[0])
    if attack_type == "pitchfork":
        return min(len(lst) for lst in payload_lists[:n_positions])
    if attack_type == "clusterbomb":
        total = 1
        for lst in payload_lists[:n_positions]:
            total *= len(lst)
        return total
    return 0


def _fire(rendered: dict, timeout_s: float = 10.0):
    """Send a single rendered request and normalize the outcome."""
    method = rendered["method"].upper()
    url = rendered["url"]
    headers = rendered["headers"]
    body = rendered["body"]
    start = time.time()
    result = {
        "status_code": None, "response_received": False, "response_gone": False,
        "error": None, "timeout": False, "length": None, "elapsed_ms": None,
        "full_response": "",
    }
    try:
        resp = requests.request(method, url, headers=headers,
                                 data=body.encode("utf-8", errors="ignore") if body else None,
                                 timeout=timeout_s, allow_redirects=False)
        result["status_code"] = resp.status_code
        result["response_received"] = True
        result["length"] = len(resp.content)
        result["full_response"] = (
            f"HTTP {resp.status_code}\r\n" +
            "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items()) +
            "\r\n\r\n" + resp.text[:20000]
        )
    except requests.exceptions.Timeout:
        result["timeout"] = True
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError as e:
        result["response_gone"] = True
        result["error"] = f"connection error: {e}"
    except Exception as e:
        result["error"] = str(e)
    result["elapsed_ms"] = (time.time() - start) * 1000.0
    return result


class AttackEngine:
    """Runs one attack session: threaded dispatch, DB persistence,
    pause/resume, and a live queue for the REPL to consume."""

    def __init__(self, db, session_id, request, attack_type, payload_lists,
                 max_workers=10, timeout_s=10.0, resume_from=-1):
        self.db = db
        self.session_id = session_id
        self.request = request
        self.attack_type = attack_type
        self.payload_lists = payload_lists
        self.max_workers = max_workers
        self.timeout_s = timeout_s

        self._pause_event = threading.Event()
        self._pause_event.set()  # set = running, cleared = paused
        self._stop_event = threading.Event()
        self.live_queue = queue.Queue()
        self._last_checkpoint = resume_from
        self._completed_since_checkpoint = 0
        self._lock = threading.Lock()
        self._thread = None
        self.total = total_request_count(request, attack_type, payload_lists)
        self.resume_from = resume_from

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def pause(self):
        # Just signal — the dispatch thread performs the authoritative
        # drain + checkpoint itself right before it blocks (see _run), so
        # there's no race between this call and in-flight result storage.
        self._pause_event.clear()
        self.db.update_session_status(self.session_id, "paused")

    def resume(self):
        self._pause_event.set()
        self.db.update_session_status(self.session_id, "running")

    def stop(self):
        self._stop_event.set()
        self._pause_event.set()  # unblock any wait

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            for req_no, payload_values, rendered in build_requests(
                    self.request, self.attack_type, self.payload_lists):
                if req_no <= self.resume_from:
                    continue  # already done in a prior run
                if self._stop_event.is_set():
                    break
                if not self._pause_event.is_set():
                    # Transitioning into paused state: fully drain everything
                    # already submitted so the persisted checkpoint reflects
                    # every stored result before we block. This must happen
                    # here (single-threaded, in the dispatch thread) rather
                    # than in pause() itself, or a result can finish storing
                    # after pause()'s checkpoint write and get silently
                    # re-run on resume.
                    self._drain_all(futures)
                    futures.clear()
                    with self._lock:
                        self.db.checkpoint(self.session_id, self._last_checkpoint)
                        self._completed_since_checkpoint = 0
                self._pause_event.wait()  # blocks here while paused
                if self._stop_event.is_set():
                    break
                fut = pool.submit(_fire, rendered, self.timeout_s)
                futures[fut] = (req_no, payload_values, rendered)

                # Drain completed futures without unbounded growth
                if len(futures) >= self.max_workers * 2:
                    self._drain_some(futures, pool)

            self._drain_all(futures)
            with self._lock:
                self.db.checkpoint(self.session_id, self._last_checkpoint)
                self._completed_since_checkpoint = 0

        if not self._stop_event.is_set():
            self.db.update_session_status(self.session_id, "completed")
        self.live_queue.put(None)  # sentinel: attack finished

    def _drain_some(self, futures, pool):
        """Block until the oldest-submitted batch of futures completes, then
        store/emit results and remove them from the in-flight dict."""
        oldest = list(futures.keys())[:self.max_workers]
        for fut in oldest:
            result = fut.result()
            req_no, payload_values, rendered = futures[fut]
            self._store_and_emit(req_no, payload_values, rendered, result)
            del futures[fut]

    def _drain_all(self, futures):
        for fut, (req_no, payload_values, rendered) in futures.items():
            result = fut.result()
            self._store_and_emit(req_no, payload_values, rendered, result)

    def _store_and_emit(self, req_no, payload_values, rendered, result):
        full_request = (
            f"{rendered['method']} {rendered['url']}\r\n" +
            "\r\n".join(f"{k}: {v}" for k, v in rendered["headers"].items()) +
            "\r\n\r\n" + (rendered["body"] or "")
        )
        self.db.insert_result(
            self.session_id, req_no, payload_values,
            result["status_code"], result["response_received"],
            result["response_gone"], result["error"], result["timeout"],
            result["length"], result["elapsed_ms"], full_request,
            result["full_response"]
        )
        with self._lock:
            self._last_checkpoint = max(self._last_checkpoint, req_no)
            self._completed_since_checkpoint += 1
            if self._completed_since_checkpoint >= CHECKPOINT_BATCH:
                self.db.checkpoint(self.session_id, self._last_checkpoint)
                self._completed_since_checkpoint = 0

        row = {"request_no": req_no, "payloads": payload_values, **result}
        self.live_queue.put(row)
