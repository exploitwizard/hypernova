# Hypernova

A CLI-based, fully interactive, fast HTTP brute-forcer — a terminal-native
replacement for Burp Suite's Proxy + Intruder combo. Capture traffic like
Burp Proxy, run Intruder-style attacks (sniper / pitchfork / battering-ram /
clusterbomb), all inside one stateful REPL session that can be paused,
resumed, filtered, and revisited from the keyboard.

## Install

One command — gives you a **global `hypernova`** command with the mitmproxy
capture engine bundled, and works on modern "externally-managed" Python
(Homebrew / Debian / Ubuntu, where a bare `pip install` is blocked):

```bash
./install.sh
```

Then, from anywhere:

```bash
hypernova
```

The installer prefers [`pipx`](https://pipx.pypa.io) (isolated + global). If
pipx isn't present it falls back to a private venv under `~/.hypernova/venv`
and links a launcher onto your `PATH`. To skip the ~40 MB mitmproxy dependency
(you can still attack `/paste`d requests), run `./install.sh --no-capture`.

<details>
<summary>Manual / developer install</summary>

```bash
# isolated global command (recommended)
pipx install .
pipx inject hypernova mitmproxy      # optional: live capture

# or a plain venv
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[capture]"          # drop [capture] to skip mitmproxy
hypernova

# or run without installing at all
python3 -m hypernova.main
```
</details>

### Windows

```powershell
py -m pip install --user pipx
py -m pipx install .
py -m pipx inject hypernova mitmproxy
```

## Workflow

```
1. /capture [port]      Start the MITM proxy (default 8090), point FoxyProxy at it
   -- or --
   /paste               Paste a raw request manually, no proxy needed
2. /select               Browse captured traffic, pick one
3. /mark                 Wrap fuzz points in §...§ (same syntax as Burp)
4. /attack                Choose attack type + payload source(s), run it
5. /filter / /filter-rv   Sort / keyword-filter the live or historical results
6. /pause /resume         Checkpointed pause, exact resume, no re-firing old requests
7. /sessions /open <id>   Revisit any past attack, expand any row's full req/resp
8. /end                   Finish and export to .txt or .html
```

Run `/help` inside the REPL any time for the full command reference.

## Architecture

```
hypernova/
├── capture.py     MITM proxy layer (mitmproxy) -> writes into SQLite automatically
├── db.py          SQLite storage: captured_traffic, attack_sessions, attack_results
├── selector.py    rich-based request browser + §§ marker editor
├── engine.py      Marker parsing + sniper/pitchfork/battering-ram/clusterbomb
│                  generators, threaded dispatch, checkpointed pause/resume,
│                  live result streaming
├── repl.py        The slash-command shell tying everything together
├── report.py      .txt / .html (collapsible, expandable) export
└── main.py        Entry point
```

### Notes on correctness

- **Marker substitution** treats the whole request (method/url/headers/body)
  as one string so `§...§` positions are found and replaced in a single,
  order-preserving pass — verified against all four attack modes with unit
  tests (sniper iterates one position at a time using the other positions'
  original values; battering-ram applies one payload to every position at
  once; pitchfork walks multiple payload lists in lockstep; clusterbomb
  takes their cartesian product).
- **Pause/resume is exact.** The dispatch thread — not an external caller —
  performs the drain-and-checkpoint before it blocks on pause, so there's no
  window where a request can finish and get stored *after* the checkpoint is
  written from another thread. This was verified with a hostile race test
  (pausing mid-batch, across process restarts, 10 repeated trials) confirming
  zero duplicate or skipped requests on resume.
- **mitmproxy is optional.** If it isn't installed, `/capture` explains how
  to install it; everything else (attacks against `/paste`d requests,
  sessions, filtering, export) works without it.

## Legal

Only point this at targets you're authorized to test (bug bounty scope,
your own infrastructure, or an engagement with signed authorization).
