"""
scope.py - Burp-style target scope matching.

A "scope" is a list of patterns. A captured request's URL is *in scope* when
it matches any pattern (or when no patterns are defined at all — an empty
scope means "everything", exactly like a fresh Burp project).

Pattern rules, kept deliberately simple and predictable:

  * A pattern containing "://" or "/" is treated as a **URL / path pattern**
    and matched against the whole URL — as a glob if it contains "*",
    otherwise as a case-insensitive substring.
        example.com/api        -> any URL containing "example.com/api"
        https://x.com/*/admin  -> glob over the full URL

  * Any other pattern is treated as a **host pattern** and matched against
    the URL's hostname — as a glob if it contains "*", otherwise matching the
    exact host, any sub-domain of it, or a host substring.
        example.com     -> example.com AND api.example.com
        *.example.com   -> api.example.com (glob)
"""

import fnmatch
from urllib.parse import urlparse


def host_of(url: str) -> str:
    """Best-effort hostname extraction that tolerates scheme-less URLs."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def matches(url: str, pattern: str) -> bool:
    """True if a single scope pattern matches the given URL."""
    pattern = (pattern or "").strip()
    if not pattern:
        return False
    low_pat, low_url = pattern.lower(), (url or "").lower()

    # URL / path pattern
    if "://" in pattern or "/" in pattern:
        if "*" in pattern:
            return fnmatch.fnmatch(low_url, low_pat)
        return low_pat in low_url

    # Host pattern
    host = host_of(url)
    if "*" in pattern:
        return fnmatch.fnmatch(host, low_pat)
    return host == low_pat or host.endswith("." + low_pat) or low_pat in host


def in_scope(url: str, patterns) -> bool:
    """True if the URL matches any pattern. An empty pattern list is 'all'."""
    if not patterns:
        return True
    return any(matches(url, p) for p in patterns)
