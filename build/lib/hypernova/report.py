"""
report.py - Export an attack session's results to .txt or .html.

.txt   - flat plain-text dump, one block per request, good for grepping
.html  - self-contained single file, collapsible <details>/<summary> rows,
         no external JS/CSS dependency, expandable like Burp's saved
         Intruder results.
"""

import json
import html as html_lib
from datetime import datetime
from jinja2 import Template

TXT_BLOCK = """\
{sep}
Request #{request_no}
Payloads: {payloads}
Status: {status_code}   Length: {length}   Time: {elapsed_ms:.1f}ms
Received: {response_received}   Gone: {response_gone}   Timeout: {timeout}
Error: {error}

--- Request ---
{full_request}

--- Response ---
{full_response}
{sep}
"""

HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Hypernova Session {{ session_id }}</title>
<style>
  body { font-family: -apple-system, Menlo, monospace; background:#0d1117; color:#c9d1d9; margin:2rem; }
  h1 { color:#58a6ff; }
  .meta { color:#8b949e; margin-bottom:1.5rem; }
  table.summary { border-collapse: collapse; margin-bottom: 2rem; width:100%; }
  table.summary th, table.summary td { border:1px solid #30363d; padding:4px 10px; text-align:left; font-size:0.9em; }
  table.summary th { background:#161b22; }
  .s2xx { color:#3fb950; } .s3xx { color:#58a6ff; } .s4xx { color:#d29922; }
  .s5xx { color:#f85149; } .stimeout { color:#d2a8ff; }
  details { border:1px solid #30363d; border-radius:6px; margin-bottom:6px; padding:6px 10px; }
  summary { cursor:pointer; }
  pre { white-space: pre-wrap; word-break: break-all; background:#161b22; padding:10px; border-radius:6px; }
</style>
</head>
<body>
<h1>Hypernova — Session {{ session_id }}</h1>
<div class="meta">
  Attack type: {{ attack_type }} &nbsp;|&nbsp;
  Target: {{ target_summary }} &nbsp;|&nbsp;
  Requests: {{ results|length }} &nbsp;|&nbsp;
  Exported: {{ exported_at }}
</div>
<table class="summary">
<tr><th>#</th><th>Payloads</th><th>Status</th><th>Length</th><th>Time (ms)</th><th>Notes</th></tr>
{% for r in results %}
<tr>
  <td>{{ r.request_no }}</td>
  <td>{{ r.payloads }}</td>
  <td class="{{ r.status_class }}">{{ r.status_code if r.status_code else '-' }}</td>
  <td>{{ r.length if r.length is not none else '-' }}</td>
  <td>{{ '%.1f'|format(r.elapsed_ms) if r.elapsed_ms else '-' }}</td>
  <td>{{ 'TIMEOUT' if r.timeout else ('GONE' if r.response_gone else (r.error or '')) }}</td>
</tr>
{% endfor %}
</table>

{% for r in results %}
<details>
<summary>#{{ r.request_no }} — {{ r.payloads }} — status {{ r.status_code if r.status_code else '-' }}</summary>
<h4>Request</h4>
<pre>{{ r.full_request }}</pre>
<h4>Response</h4>
<pre>{{ r.full_response }}</pre>
</details>
{% endfor %}
</body>
</html>
""")


def _status_class(status_code, timeout):
    if timeout:
        return "stimeout"
    if status_code is None:
        return ""
    return f"s{status_code // 100}xx"


def export_txt(session, results, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Hypernova Session {session['session_id']}\n")
        f.write(f"Attack type: {session['attack_type']}\n")
        f.write(f"Target: {session.get('target_summary', '')}\n")
        f.write(f"Exported: {datetime.now().isoformat()}\n")
        for r in results:
            f.write(TXT_BLOCK.format(
                sep="=" * 70,
                request_no=r["request_no"],
                payloads=json.loads(r["payloads"]) if isinstance(r["payloads"], str) else r["payloads"],
                status_code=r["status_code"],
                length=r["length"],
                elapsed_ms=r["elapsed_ms"] or 0.0,
                response_received=bool(r["response_received"]),
                response_gone=bool(r["response_gone"]),
                timeout=bool(r["timeout"]),
                error=r["error"] or "",
                full_request=r["full_request"] or "",
                full_response=r["full_response"] or "",
            ))
    return path


def export_html(session, results, path):
    enriched = []
    for r in results:
        payloads = json.loads(r["payloads"]) if isinstance(r["payloads"], str) else r["payloads"]
        enriched.append({
            "request_no": r["request_no"],
            "payloads": html_lib.escape(str(payloads)),
            "status_code": r["status_code"],
            "length": r["length"],
            "elapsed_ms": r["elapsed_ms"],
            "timeout": bool(r["timeout"]),
            "response_gone": bool(r["response_gone"]),
            "error": html_lib.escape(r["error"] or ""),
            "full_request": html_lib.escape(r["full_request"] or ""),
            "full_response": html_lib.escape(r["full_response"] or ""),
            "status_class": _status_class(r["status_code"], r["timeout"]),
        })
    rendered = HTML_TEMPLATE.render(
        session_id=session["session_id"],
        attack_type=session["attack_type"],
        target_summary=session.get("target_summary", ""),
        results=enriched,
        exported_at=datetime.now().isoformat(),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(rendered)
    return path


def export(session, results, path):
    if path.endswith(".html"):
        return export_html(session, results, path)
    return export_txt(session, results, path)
