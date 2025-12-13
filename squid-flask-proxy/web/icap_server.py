from __future__ import annotations

from collections import Counter, OrderedDict
from dataclasses import dataclass
import gzip
import os
import re
import socket
import socketserver
import struct
import threading
import time
import urllib.parse
import heapq
import zlib
from html import escape as _html_escape
from typing import Dict, List, Optional, Set, Tuple

try:
    import brotli  # type: ignore
except Exception:  # pragma: no cover
    brotli = None  # type: ignore

from services.adblock_store import get_adblock_store
from services.preload_store import get_preload_store
from services.clamav_store import get_clamav_store

_CLAMAV_SOCKET_PATH = "/var/lib/squid-flask-proxy/clamav/clamd.sock"

_CLAMAV_SETTINGS_LAST = 0
_CLAMAV_SETTINGS_MAX_SCAN = 134217728


def _clamav_get_max_scan_bytes(store) -> int:
    global _CLAMAV_SETTINGS_LAST, _CLAMAV_SETTINGS_MAX_SCAN
    now = _now()
    if now - _CLAMAV_SETTINGS_LAST < 5:
        return int(_CLAMAV_SETTINGS_MAX_SCAN)
    try:
        settings = store.get_settings()
        v = int(settings.get("max_scan_bytes") or 134217728)
        if v < 1:
            v = 134217728
        _CLAMAV_SETTINGS_MAX_SCAN = v
    except Exception:
        _CLAMAV_SETTINGS_MAX_SCAN = 134217728
    _CLAMAV_SETTINGS_LAST = now
    return int(_CLAMAV_SETTINGS_MAX_SCAN)

try:
    from adblockparser import AdblockRules
except Exception:  # pragma: no cover
    AdblockRules = None  # type: ignore

try:
    import re2  # type: ignore  # noqa: F401
    _HAS_RE2 = True
except Exception:  # pragma: no cover
    _HAS_RE2 = False


def _now() -> int:
    return int(time.time())


class _Ruleset:
    def __init__(self) -> None:
        self.version = 0
        self.enabled: Dict[str, bool] = {}
        self.matcher: Optional[_CandidateMatcher] = None


_TOKEN_MIN_LEN = 4
_MAX_TOKENS_PER_RULE = 4
_MAX_URL_TOKENS = 96


class _Aho:
    def __init__(self) -> None:
        # Each node: {next: {ch: node_id}, fail: node_id, out: [pattern]}
        self._next: List[Dict[str, int]] = [dict()]
        self._fail: List[int] = [0]
        self._out: List[List[str]] = [[]]
        self._built = False

    def add(self, pat: str) -> None:
        p = (pat or "").strip().lower()
        if not p:
            return
        node = 0
        for ch in p:
            nxt = self._next[node].get(ch)
            if nxt is None:
                nxt = len(self._next)
                self._next[node][ch] = nxt
                self._next.append({})
                self._fail.append(0)
                self._out.append([])
            node = nxt
        self._out[node].append(p)

    def build(self) -> None:
        # Classic BFS fail-link construction.
        from collections import deque

        q = deque()
        # Depth-1 nodes fail to root.
        for ch, nxt in self._next[0].items():
            self._fail[nxt] = 0
            q.append(nxt)

        while q:
            v = q.popleft()
            for ch, nxt in self._next[v].items():
                q.append(nxt)
                f = self._fail[v]
                while f and ch not in self._next[f]:
                    f = self._fail[f]
                self._fail[nxt] = self._next[f].get(ch, 0)
                # Merge outputs.
                if self._out[self._fail[nxt]]:
                    self._out[nxt].extend(self._out[self._fail[nxt]])

        self._built = True

    def iter_matches(self, text: str) -> List[Tuple[int, str]]:
        # Returns (end_index, pattern)
        if not self._built:
            return []
        t = (text or "").lower()
        node = 0
        out: List[Tuple[int, str]] = []
        for i, ch in enumerate(t):
            while node and ch not in self._next[node]:
                node = self._fail[node]
            node = self._next[node].get(ch, 0)
            if self._out[node]:
                for pat in self._out[node]:
                    out.append((i, pat))
        return out


@dataclass(frozen=True)
class _RuleEntry:
    order: int
    list_key: str
    rule: object
    is_exception: bool
    host_keys: Tuple[str, ...]
    token_keys: Tuple[str, ...]
    third_party_opt: Optional[bool]


def _host_suffixes(host: str) -> List[str]:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return []
    parts = [p for p in h.split(".") if p]
    out: List[str] = []
    # Avoid indexing on a bare TLD (e.g. "com") because it creates massive candidate sets.
    start_n = 2 if len(parts) >= 2 else 1
    for n in range(start_n, min(4, len(parts) + 1)):
        suf = ".".join(parts[-n:])
        if "." in suf:
            out.append(suf)
    # Prefer most specific first.
    return out


def _literal_runs_from_regex(rx: str) -> List[str]:
    # Extract plausible literal substrings from a regex pattern.
    # We keep runs that are likely to appear verbatim in URLs.
    s = (rx or "")
    out: List[str] = []
    cur: List[str] = []
    in_class = False
    i = 0
    while i < len(s):
        ch = s[i]
        if in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            if cur:
                out.append("".join(cur))
                cur = []
            in_class = True
            i += 1
            continue
        if ch == "\\":
            if i + 1 < len(s):
                nxt = s[i + 1]
                # Common escaped literals used in adblockparser-generated regex.
                if nxt.isalnum() and nxt in "dDsSwWbB":
                    if cur:
                        out.append("".join(cur))
                        cur = []
                else:
                    # Treat unknown escapes as the escaped literal.
                    if nxt in ".-_/:%":
                        cur.append(nxt)
                    elif nxt.isalnum():
                        cur.append(nxt)
                    else:
                        if cur:
                            out.append("".join(cur))
                            cur = []
                i += 2
                continue
            # Trailing backslash.
            if cur:
                out.append("".join(cur))
                cur = []
            i += 1
            continue

        if ch.isalnum() or ch in "._-/%":
            cur.append(ch)
        else:
            if cur:
                out.append("".join(cur))
                cur = []
        i += 1
    if cur:
        out.append("".join(cur))
    return out


_TOKEN_STOPWORDS = {
    "http",
    "https",
    "www",
    "html",
    "php",
    "asp",
    "aspx",
    "json",
    "index",
    "main",
    "static",
    "assets",
    "content",
    "api",
    "pixel",
}


def _extract_rule_keys(rule: object) -> Tuple[Set[str], Set[str]]:
    # Returns (host_candidates, token_candidates)
    try:
        rule_text = getattr(rule, "rule_text", "") or ""
        raw = getattr(rule, "raw_rule_text", "") or ""
        rx = getattr(rule, "regex", "") or ""
    except Exception:
        return set(), set()

    # If it's a /regex/ rule, use the compiled regex source; otherwise use the ABP-ish rule_text.
    is_explicit_regex = rule_text.startswith("/") and rule_text.endswith("/") and len(rule_text) > 2
    if is_explicit_regex:
        runs = _literal_runs_from_regex(rx)
    else:
        s = rule_text
        # Normalize common ABP anchors/wildcards into separators.
        s = s.replace("*", " ").replace("^", " ")
        s = s.replace("||", " ").replace("|", " ")
        runs = re.findall(r"[A-Za-z0-9._%/-]+", s)
        # Some rules are plain substrings (e.g. 'badpattern'); treat that as a run.
        if not runs and s:
            runs = [s]

    host_candidates: Set[str] = set()
    token_candidates: Set[str] = set()

    for r in runs:
        t = (r or "").strip().lower().strip(".")
        if not t:
            continue

        # Heuristic: domain-ish literals become host keys.
        if "." in t and "/" not in t and ":" not in t and len(t) >= 6:
            for suf in _host_suffixes(t):
                host_candidates.add(suf)

        # Tokenize for path/query matching.
        for part in re.split(r"[^a-z0-9]+", t):
            p = (part or "").strip().lower()
            if len(p) < _TOKEN_MIN_LEN:
                continue
            if p.isdigit():
                continue
            if p in _TOKEN_STOPWORDS:
                continue
            token_candidates.add(p)

    # Fallback: include words from raw rule text.
    if raw:
        for part in re.split(r"[^a-z0-9]+", raw.lower()):
            if len(part) < _TOKEN_MIN_LEN:
                continue
            if part.isdigit() or part in _TOKEN_STOPWORDS:
                continue
            token_candidates.add(part)

    return host_candidates, token_candidates


class _CandidateMatcher:
    def __init__(self, entries: List[_RuleEntry]) -> None:
        self._entries = entries
        self._host_index: Dict[str, List[int]] = {}
        self._token_index: Dict[str, List[int]] = {}
        self._fallback_exception_ids: List[int] = []
        self._fallback_block_ids: List[int] = []
        self._aho: Optional[_Aho] = None

        for idx, ent in enumerate(entries):
            added = False
            for hk in ent.host_keys:
                self._host_index.setdefault(hk, []).append(idx)
                added = True
            for tk in ent.token_keys:
                self._token_index.setdefault(tk, []).append(idx)
                added = True
            if not added:
                if ent.is_exception:
                    self._fallback_exception_ids.append(idx)
                else:
                    self._fallback_block_ids.append(idx)

        # Build a token automaton for one-pass URL scanning.
        try:
            if self._token_index:
                aho = _Aho()
                for tok in self._token_index.keys():
                    aho.add(tok)
                aho.build()
                self._aho = aho
        except Exception:
            self._aho = None

    def _iter_url_tokens(self, path_query_lc: str) -> Set[str]:
        toks: Set[str] = set()
        text = (path_query_lc or "")

        # Fast path: Aho–Corasick over known tokens.
        if self._aho is not None and text:
            for end_i, pat in self._aho.iter_matches(text):
                # Enforce token boundaries to reduce false positives.
                start_i = end_i - len(pat) + 1
                if start_i < 0:
                    continue
                if start_i > 0 and text[start_i - 1].isalnum():
                    continue
                if end_i + 1 < len(text) and text[end_i + 1].isalnum():
                    continue
                toks.add(pat)
                if len(toks) >= _MAX_URL_TOKENS:
                    break
            return toks

        # Fallback: split on non-alnum.
        for part in re.split(r"[^a-z0-9]+", text):
            if len(part) >= _TOKEN_MIN_LEN:
                toks.add(part)
                if len(toks) >= _MAX_URL_TOKENS:
                    break
        return toks

    def _candidate_ordered_ids(self, host: str, tokens: Set[str]) -> List[int]:
        # K-way merge of already-ordered index lists to produce a sorted, de-duplicated
        # candidate id list without building a large set + sorting it.
        lists: List[List[int]] = []
        for suf in _host_suffixes(host):
            lst = self._host_index.get(suf)
            if lst:
                lists.append(lst)
        for tok in tokens:
            lst = self._token_index.get(tok)
            if lst:
                lists.append(lst)

        if not lists:
            return []

        heap: List[Tuple[int, int, int]] = []
        for li, lst in enumerate(lists):
            heap.append((lst[0], li, 0))
        heapq.heapify(heap)

        out: List[int] = []
        last: Optional[int] = None
        while heap:
            val, li, pos = heapq.heappop(heap)
            if last != val:
                out.append(val)
                last = val
            nxt_pos = pos + 1
            lst = lists[li]
            if nxt_pos < len(lst):
                heapq.heappush(heap, (lst[nxt_pos], li, nxt_pos))
        return out

    def _tp_compatible(self, ent: _RuleEntry, third_party: Optional[bool]) -> bool:
        if ent.third_party_opt is None or third_party is None:
            return True
        return bool(ent.third_party_opt) is bool(third_party)

    def match(self, url: str, *, document_host: str = "", third_party: Optional[bool] = None) -> Optional[str]:
        # Return list_key that matched a blocking rule, else None.
        try:
            sp = urllib.parse.urlsplit(url)
            host = (sp.hostname or "").strip().lower().rstrip(".")
            path_query_lc = ((sp.path or "") + "?" + (sp.query or "")).lower()
        except Exception:
            host = ""
            path_query_lc = ""

        tokens = self._iter_url_tokens(path_query_lc)
        ordered = self._candidate_ordered_ids(host, tokens)
        if not ordered and not self._fallback_exception_ids and not self._fallback_block_ids:
            return None

        opts: Dict[str, object] = {}
        doc = (document_host or "").strip().lower().rstrip(".")
        if doc:
            opts["domain"] = doc
        if third_party is True:
            opts["third-party"] = True
        elif third_party is False:
            opts["third-party"] = False

        if ordered:
            # ABP semantics: exceptions override blocks (globally).
            for idx in ordered:
                ent = self._entries[idx]
                if not ent.is_exception:
                    continue
                if not self._tp_compatible(ent, third_party):
                    continue
                try:
                    if getattr(ent.rule, "match_url")(url, opts):
                        return None
                except Exception:
                    continue

        # Exceptions that were not indexable.
        for idx in self._fallback_exception_ids:
            ent = self._entries[idx]
            if not self._tp_compatible(ent, third_party):
                continue
            try:
                if getattr(ent.rule, "match_url")(url, opts):
                    return None
            except Exception:
                continue

        if ordered:
            for idx in ordered:
                ent = self._entries[idx]
                if ent.is_exception:
                    continue
                if not self._tp_compatible(ent, third_party):
                    continue
                try:
                    if getattr(ent.rule, "match_url")(url, opts):
                        return ent.list_key
                except Exception:
                    continue

        # Blocking rules that were not indexable.
        for idx in self._fallback_block_ids:
            ent = self._entries[idx]
            if not self._tp_compatible(ent, third_party):
                continue
            try:
                if getattr(ent.rule, "match_url")(url, opts):
                    return ent.list_key
            except Exception:
                continue
        return None


def _parse_icap_headers(data: bytes) -> Tuple[Dict[str, str], bytes]:
    # Returns headers dict and remaining bytes after ICAP headers.
    sep = b"\r\n\r\n"
    idx = data.find(sep)
    if idx < 0:
        return {}, b""
    head = data[:idx].decode("iso-8859-1", errors="replace")
    rest = data[idx + 4 :]
    lines = head.split("\r\n")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return headers, rest


def _parse_encapsulated_offset(enc: str) -> Dict[str, int]:
    # Example: "req-hdr=0, null-body=123"
    out: Dict[str, int] = {}
    for part in (enc or "").split(","):
        p = part.strip()
        if not p or "=" not in p:
            continue
        k, v = p.split("=", 1)
        try:
            out[k.strip().lower()] = int(v.strip())
        except Exception:
            pass
    return out


def _extract_http_request(enc_body: bytes, offsets: Dict[str, int]) -> str:
    # We only care about req-hdr.
    start = offsets.get("req-hdr")
    if start is None:
        return ""

    # Next section begins at the smallest offset > start.
    next_off = None
    for v in offsets.values():
        if v > start and (next_off is None or v < next_off):
            next_off = v
    end = next_off if next_off is not None else len(enc_body)

    chunk = enc_body[start:end]
    try:
        return chunk.decode("iso-8859-1", errors="replace")
    except Exception:
        return ""


def _parse_url_from_http_request(req_hdr: str) -> str:
    # Request line may be absolute-form: GET http://host/path HTTP/1.1
    # or origin-form: GET /path HTTP/1.1 with Host header.
    lines = (req_hdr or "").split("\r\n")
    if not lines:
        return ""
    parts = lines[0].split()
    if len(parts) < 2:
        return ""
    target = parts[1]
    if target.startswith("http://") or target.startswith("https://"):
        return target

    host = ""
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    if not host:
        return ""
    # Default to http when unknown.
    if not target.startswith("/"):
        target = "/" + target
    return f"http://{host}{target}"


def _parse_method_and_target(req_hdr: str) -> Tuple[str, str]:
    lines = (req_hdr or "").split("\r\n")
    if not lines:
        return "", ""
    parts = lines[0].split()
    if len(parts) < 2:
        return "", ""
    return parts[0].upper(), parts[1]


def _host_from_url(url: str) -> str:
    try:
        h = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        h = ""
    return (h or "").strip().lower().rstrip(".")


def _icap_204() -> bytes:
    return (
        b"ICAP/1.0 204 No Content\r\n"
        b"Connection: close\r\n"
        b"Encapsulated: null-body=0\r\n"
        b"\r\n"
    )


def _icap_options(service: str = "") -> bytes:
    # Squid sends OPTIONS to learn service capabilities.
    # We support both REQMOD (adblock) and RESPMOD (html rewrite).
    svc = (service or "").strip().lower().lstrip("/")
    if svc == "respmod":
        methods = "RESPMOD"
        name = "squid-flask-proxy-html-preload"
        istag = "sfp-html-preload-1"
    elif svc == "avrespmod":
        methods = "RESPMOD"
        name = "squid-flask-proxy-clamav"
        istag = "sfp-clamav-1"
    elif svc == "reqmod":
        methods = "REQMOD"
        name = "squid-flask-proxy-adblock"
        istag = "sfp-adblock-1"
    else:
        methods = "REQMOD, RESPMOD"
        name = "squid-flask-proxy"
        istag = "sfp-1"

    return (
        b"ICAP/1.0 200 OK\r\n"
        b"Connection: close\r\n"
        + f"Methods: {methods}\r\n".encode("ascii")
        + f"Service: {name}\r\n".encode("ascii")
        + f"ISTag: \"{istag}\"\r\n".encode("ascii")
        + b"Options-TTL: 3600\r\n"
        + b"Allow: 204\r\n"
        + b"Encapsulated: null-body=0\r\n"
        + b"\r\n"
    )


def _parse_icap_first_line(first_line: str) -> Tuple[str, str]:
    # Returns (method, service_path)
    # Example: "REQMOD icap://127.0.0.1:1344/reqmod ICAP/1.0"
    s = (first_line or "").strip()
    parts = s.split()
    if not parts:
        return "", ""
    method = parts[0].upper()
    service_path = ""
    if len(parts) >= 2:
        try:
            service_path = urllib.parse.urlsplit(parts[1]).path or ""
        except Exception:
            service_path = ""
    return method, service_path


def _extract_http_response(enc_body: bytes, offsets: Dict[str, int]) -> str:
    start = offsets.get("res-hdr")
    if start is None:
        return ""

    next_off = None
    for v in offsets.values():
        if v > start and (next_off is None or v < next_off):
            next_off = v
    end = next_off if next_off is not None else len(enc_body)

    chunk = enc_body[start:end]
    try:
        return chunk.decode("iso-8859-1", errors="replace")
    except Exception:
        return ""


def _parse_http_headers_block(hdr: str) -> Tuple[str, Dict[str, str]]:
    lines = (hdr or "").split("\r\n")
    if not lines:
        return "", {}
    status = lines[0]
    out: Dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip().lower()] = v.strip()
    return status, out


def _remove_headers(hdr_lines: List[str], names: Set[str]) -> List[str]:
    deny = {n.lower() for n in names}
    out: List[str] = []
    for line in hdr_lines:
        if ":" not in line:
            out.append(line)
            continue
        k = line.split(":", 1)[0].strip().lower()
        if k in deny:
            continue
        out.append(line)
    return out


def _decode_icap_chunked(data: bytes, max_out: int = 8 * 1024 * 1024) -> Tuple[bytes, bool]:
    # Decode ICAP chunked body (hex size + CRLF + data + CRLF ... + 0 CRLF CRLF)
    out = bytearray()
    i = 0
    n = len(data)

    def read_line() -> Optional[bytes]:
        nonlocal i
        j = data.find(b"\r\n", i)
        if j < 0:
            return None
        line = data[i:j]
        i = j + 2
        return line

    while True:
        line = read_line()
        if line is None:
            return bytes(out), False
        # ignore chunk extensions
        try:
            size_str = line.split(b";", 1)[0].strip()
            size = int(size_str.decode("ascii", errors="ignore") or "0", 16)
        except Exception:
            return bytes(out), False
        if size == 0:
            # Expect trailing CRLF after 0-size chunk and optional trailers.
            # We accept either immediate CRLF or trailers ending in CRLF CRLF.
            # If there's not enough data, mark incomplete.
            # Consume the final CRLF if present.
            if i + 2 <= n and data[i : i + 2] == b"\r\n":
                i += 2
            else:
                # Try to find end of trailers.
                end = data.find(b"\r\n\r\n", i)
                if end < 0:
                    return bytes(out), False
                i = end + 4
            return bytes(out), True

        if i + size + 2 > n:
            return bytes(out), False
        out += data[i : i + size]
        if len(out) > max_out:
            return bytes(out[:max_out]), True
        i += size
        # chunk CRLF
        if data[i : i + 2] != b"\r\n":
            return bytes(out), False
        i += 2


def _maybe_decompress(body: bytes, encoding: str) -> Tuple[Optional[bytes], str]:
    enc = (encoding or "").strip().lower()
    if not enc or enc == "identity":
        return body, "identity"
    if enc == "gzip":
        try:
            return gzip.decompress(body), "gzip"
        except Exception:
            return None, ""
    if enc == "deflate":
        # Deflate can be zlib-wrapped or raw.
        try:
            return zlib.decompress(body), "deflate-zlib"
        except Exception:
            try:
                return zlib.decompress(body, wbits=-zlib.MAX_WBITS), "deflate-raw"
            except Exception:
                return None, ""
    if enc == "br":
        # Brotli-compressed responses (common on modern sites).
        if brotli is None:
            return None, ""
        try:
            return brotli.decompress(body), "br"
        except Exception:
            return None, ""
    return None, ""


def _recompress(body: bytes, style: str) -> Tuple[bytes, str]:
    if style == "identity":
        return body, ""
    if style == "gzip":
        return gzip.compress(body), "gzip"
    if style == "deflate-zlib":
        return zlib.compress(body), "deflate"
    if style == "deflate-raw":
        c = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
        return c.compress(body) + c.flush(), "deflate"
    if style == "br":
        if brotli is None:
            return body, ""
        # Moderate quality for CPU balance; mode text helps HTML.
        try:
            mode_text = getattr(brotli, "MODE_TEXT", 0)
            return brotli.compress(body, quality=5, mode=mode_text), "br"
        except TypeError:
            # Older brotli bindings may not accept keyword args.
            try:
                return brotli.compress(body), "br"
            except Exception:
                return body, ""
    # fallback: no encoding
    return body, ""


_IMG_SRC_RE = re.compile(r"<img\b[^>]*\bsrc\s*=\s*(['\"])(.*?)\1", re.I | re.S)


def _inject_preloads_into_html(html_text: str) -> Tuple[Optional[str], int]:
    s = html_text or ""
    m = re.search(r"</head\s*>", s, flags=re.I)
    if not m:
        # no <head>, don't risk breaking markup
        return None, 0

    urls: List[str] = []
    seen: Set[str] = set()
    for _m in _IMG_SRC_RE.finditer(s):
        u = (_m.group(2) or "").strip()
        if not u:
            continue
        if u.startswith("data:"):
            continue
        if u in seen:
            continue
        seen.add(u)
        urls.append(u)

    if not urls:
        return None, 0

    preload_lines = [
        f"<link rel=\"preload\" as=\"image\" href=\"{_html_escape(u, quote=True)}\">" for u in urls
    ]
    inject = "\n" + "\n".join(preload_lines) + "\n"
    return s[: m.start()] + inject + s[m.start() :], len(urls)


def _build_icap_resp_with_http(http_hdr_text: str, body_bytes: bytes) -> bytes:
    # ICAP encapsulated body uses HTTP chunked framing.
    chunk_prefix = f"{len(body_bytes):X}\r\n".encode("ascii")
    http_body = chunk_prefix + body_bytes + b"\r\n0\r\n\r\n"
    http_hdr_bytes = http_hdr_text.encode("iso-8859-1", errors="replace")
    return (
        b"ICAP/1.0 200 OK\r\n"
        b"Connection: close\r\n"
        + f"Encapsulated: res-hdr=0, res-body={len(http_hdr_bytes)}\r\n".encode("ascii")
        + b"\r\n"
        + http_hdr_bytes
        + http_body
    )


def _icap_block_403(url: str) -> bytes:
    body = (
        "<html><head><title>Blocked</title></head>"
        "<body><h1>Blocked</h1>"
        "<p>Request blocked by ICAP ad blocker.</p>"
        f"<p style='font-family: monospace;'>{url}</p>"
        "</body></html>"
    ).encode("utf-8")

    http_hdr = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        b"\r\n"
    )

    # ICAP encapsulated body uses HTTP chunked framing.
    chunk_prefix = f"{len(body):X}\r\n".encode("ascii")
    http_body = chunk_prefix + body + b"\r\n0\r\n\r\n"

    return (
        b"ICAP/1.0 200 OK\r\n"
        b"Connection: close\r\n"
        + f"Encapsulated: res-hdr=0, res-body={len(http_hdr)}\r\n".encode("ascii")
        + b"\r\n"
        + http_hdr
        + http_body
    )


def _icap_virus_block_403(url: str, virus: str) -> bytes:
    v = (virus or "malware").strip()[:200]
    body = (
        "<html><head><title>Blocked</title></head>"
        "<body><h1>Blocked</h1>"
        "<p>Response blocked by ClamAV.</p>"
        f"<p><strong>Detection:</strong> <span style='font-family: monospace;'>{_html_escape(v)}</span></p>"
        + (f"<p style='font-family: monospace;'>{_html_escape(url)}</p>" if url else "")
        + "</body></html>"
    ).encode("utf-8")

    http_hdr = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        b"\r\n"
    )
    chunk_prefix = f"{len(body):X}\r\n".encode("ascii")
    http_body = chunk_prefix + body + b"\r\n0\r\n\r\n"
    return (
        b"ICAP/1.0 200 OK\r\n"
        b"Connection: close\r\n"
        + f"Encapsulated: res-hdr=0, res-body={len(http_hdr)}\r\n".encode("ascii")
        + b"\r\n"
        + http_hdr
        + http_body
    )


def _clamd_instream_scan(data: bytes, sock_path: str, timeout_s: float = 2.5) -> Tuple[str, str]:
    # Returns (status, detail)
    # status: 'clean'|'infected'|'error'
    # detail: virus name for infected, or error string
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        s.connect(sock_path)

        s.sendall(b"zINSTREAM\0")
        mv = memoryview(data)
        chunk = 32 * 1024
        off = 0
        while off < len(mv):
            n = min(chunk, len(mv) - off)
            s.sendall(struct.pack("!I", n))
            s.sendall(mv[off : off + n])
            off += n
        s.sendall(struct.pack("!I", 0))

        resp = s.recv(4096)
        s.close()
        text = resp.decode("utf-8", errors="replace").strip()
        if "FOUND" in text:
            # e.g. 'stream: Eicar-Test-Signature FOUND'
            name = text.split(":", 1)[-1].strip()
            name = name.replace("FOUND", "").strip() or "malware"
            return "infected", name
        if text.endswith("OK"):
            return "clean", "OK"
        return "error", (text or "unexpected clamd response")
    except Exception as e:
        return "error", f"{type(e).__name__}: {e}"


class IcapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            # Read a reasonable amount; ICAP headers + req-hdr typically fit.
            self.request.settimeout(10)
            buf = b""
            try:
                while b"\r\n\r\n" not in buf and len(buf) < 65536:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
            except TimeoutError:
                # Best-effort: respond allow rather than hanging Squid.
                try:
                    self.request.sendall(_icap_204())
                except Exception:
                    pass
                return

            # ICAP request line is the first line.
            try:
                first_line = buf.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            except Exception:
                first_line = ""
            icap_method, service_path = _parse_icap_first_line(first_line)
            if icap_method == "OPTIONS" or first_line.upper().startswith("OPTIONS "):
                try:
                    self.request.sendall(_icap_options(service_path))
                except Exception:
                    pass
                return

            headers, rest = _parse_icap_headers(buf)
            enc = headers.get("encapsulated", "")
            offsets = _parse_encapsulated_offset(enc)

            if icap_method == "RESPMOD":
                svc = (service_path or "").strip().lower().lstrip("/")
                if svc == "avrespmod":
                    self._handle_av_respmod(offsets, rest)
                else:
                    self._handle_respmod(offsets, rest)
                return

        except (ConnectionResetError, BrokenPipeError):
            # Squid may close/reset connections while we're reading or writing.
            return
        except OSError as e:
            # Treat common socket disconnect errors as non-fatal; surface the rest.
            if getattr(e, "errno", None) in (32, 54, 104):
                return
            raise

        if icap_method != "REQMOD":
            # Unknown method.
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Ensure we have enough bytes for req-hdr.
        needed = 0
        if "req-hdr" in offsets:
            # Need at least through the next offset section.
            next_off = None
            start = offsets.get("req-hdr", 0)
            for v in offsets.values():
                if v > start and (next_off is None or v < next_off):
                    next_off = v
            needed = next_off if next_off is not None else 8192

        # Read more if necessary.
        try:
            while len(rest) < needed and len(rest) < 131072:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                rest += chunk
        except TimeoutError:
            # Best-effort: treat incomplete request as allow.
            self.request.sendall(_icap_204())
            return

        req_hdr = _extract_http_request(rest, offsets)
        method, target = _parse_method_and_target(req_hdr)
        url = _parse_url_from_http_request(req_hdr)

        # Parse HTTP headers for basic context.
        http_headers: Dict[str, str] = {}
        try:
            lines = (req_hdr or "").split("\r\n")
            for line in lines[1:]:
                if not line or ":" not in line:
                    continue
                k, v = line.split(":", 1)
                http_headers[k.strip().lower()] = v.strip()
        except Exception:
            http_headers = {}

        if not url or not self.server.engine:
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # We do not block at CONNECT time. CONNECT lacks enough request context
        # (third-party, document domain, resource type) and can overblock.
        if method == "CONNECT":
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Adblock rules depend heavily on context like third-party and document domain.
        # We approximate using Sec-Fetch-Site when present, falling back to Referer.
        request_host = _host_from_url(url)

        sec_fetch_site = (http_headers.get("sec-fetch-site") or "").strip().lower()
        third_party: Optional[bool] = None
        if sec_fetch_site == "cross-site":
            third_party = True
        elif sec_fetch_site in ("same-origin", "same-site", "none"):
            third_party = False
        else:
            ref = (http_headers.get("referer") or "").strip()
            ref_host = _host_from_url(ref) if ref else ""
            if request_host and ref_host:
                same_site = (
                    request_host == ref_host
                    or request_host.endswith("." + ref_host)
                    or ref_host.endswith("." + request_host)
                )
                third_party = not same_site

        doc_host = _host_from_url((http_headers.get("referer") or "").strip())
        if not doc_host:
            doc_host = request_host

        blocked_by = self.server.engine.should_block(url, document_host=doc_host, third_party=third_party)
        if blocked_by:
            self.server.engine.record(blocked_by)
            try:
                self.request.sendall(_icap_block_403(url))
            except Exception:
                pass
            return

        try:
            self.request.sendall(_icap_204())
        except Exception:
            pass

    def _handle_respmod(self, offsets: Dict[str, int], enc_rest: bytes) -> None:
        # Only rewrite HTML responses with supported content encodings.
        # Squid sends HTTP response header in res-hdr and body in res-body (ICAP chunked).

        store = get_preload_store()
        try:
            store.record_seen()
        except Exception:
            pass

        try:
            self._handle_respmod_inner(offsets, enc_rest, store)
            return
        except Exception as e:
            try:
                store.record_failure(f"unhandled_exception: {type(e).__name__}: {e}")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass

    def _handle_av_respmod(self, offsets: Dict[str, int], enc_rest: bytes) -> None:
        store = get_clamav_store()
        try:
            store.record_seen()
        except Exception:
            pass

        try:
            self._handle_av_respmod_inner(offsets, enc_rest, store)
            return
        except Exception as e:
            try:
                store.record_error(f"unhandled_exception: {type(e).__name__}: {e}")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass

    def _handle_av_respmod_inner(self, offsets: Dict[str, int], enc_rest: bytes, store) -> None:
        # Ensure we have res-hdr and res-body.
        if "res-hdr" not in offsets or "res-body" not in offsets:
            try:
                store.record_skip("missing_parts")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Read enough to include res-hdr at least.
        needed = 0
        start = offsets.get("res-hdr", 0)
        next_off = None
        for v in offsets.values():
            if v > start and (next_off is None or v < next_off):
                next_off = v
        needed = next_off if next_off is not None else (start + 4096)

        rest = enc_rest
        try:
            while len(rest) < needed and len(rest) < 256 * 1024:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                rest += chunk
        except TimeoutError:
            try:
                store.record_error("timeout_reading_res_hdr")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        res_hdr_text = _extract_http_response(rest, offsets)
        if not res_hdr_text:
            try:
                store.record_skip("missing_parts")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        _status_line, headers = _parse_http_headers_block(res_hdr_text)
        ctype = (headers.get("content-type") or "").strip().lower()
        if ctype.startswith("image/") or ctype.startswith("video/"):
            try:
                store.record_skip("image_video")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Collect full ICAP chunked body (cap reads).
        body_off = offsets.get("res-body", 0)
        if body_off >= len(rest):
            try:
                while len(rest) < body_off + 8 and len(rest) < 8 * 1024 * 1024:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
            except TimeoutError:
                try:
                    self.request.sendall(_icap_204())
                except Exception:
                    pass
                return

        body_chunked = rest[body_off:]
        try:
            while b"\r\n0\r\n\r\n" not in body_chunked and len(body_chunked) < 140 * 1024 * 1024:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                body_chunked += chunk
        except TimeoutError:
            pass

        raw_http_body, complete = _decode_icap_chunked(body_chunked, max_out=140 * 1024 * 1024)
        if not complete:
            try:
                store.record_skip("incomplete_body")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        max_scan = _clamav_get_max_scan_bytes(store)

        enc = headers.get("content-encoding") or ""
        dec, _style = _maybe_decompress(raw_http_body, enc)
        if dec is None:
            try:
                store.record_skip("unsupported_encoding")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        if len(dec) > max_scan:
            try:
                store.record_skip("too_large")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        status, detail = _clamd_instream_scan(dec, sock_path=_CLAMAV_SOCKET_PATH)

        if status == "clean":
            try:
                store.record_scanned(clean=True, infected=False)
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        if status == "infected":
            try:
                store.record_scanned(clean=False, infected=True)
            except Exception:
                pass

            url = ""
            try:
                req_hdr = _extract_http_request(rest, offsets)
                url = _parse_url_from_http_request(req_hdr)
            except Exception:
                url = ""

            try:
                self.request.sendall(_icap_virus_block_403(url, detail))
            except Exception:
                pass
            return

        # error
        try:
            store.record_error(str(detail))
        except Exception:
            pass
        try:
            self.request.sendall(_icap_204())
        except Exception:
            pass

    def _handle_respmod_inner(self, offsets: Dict[str, int], enc_rest: bytes, store) -> None:
        # Split out for a single try/except wrapper in _handle_respmod.

        try:
            print(f"[icap respmod] start offsets={sorted(offsets.items())}", flush=True)
        except Exception:
            pass

        # Ensure we have res-hdr.
        if "res-hdr" not in offsets or "res-body" not in offsets:
            try:
                store.record_skip("missing_parts")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Read enough to include res-hdr at least.
        needed = 0
        start = offsets.get("res-hdr", 0)
        next_off = None
        for v in offsets.values():
            if v > start and (next_off is None or v < next_off):
                next_off = v
        needed = next_off if next_off is not None else (start + 4096)

        rest = enc_rest
        try:
            while len(rest) < needed and len(rest) < 256 * 1024:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                rest += chunk
        except TimeoutError:
            try:
                store.record_failure("timeout_reading_res_hdr")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        res_hdr_text = _extract_http_response(rest, offsets)
        if not res_hdr_text:
            try:
                print("[icap respmod] no res-hdr extracted -> 204", flush=True)
            except Exception:
                pass
            try:
                store.record_skip("missing_parts")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Parse headers.
        status_line, headers = _parse_http_headers_block(res_hdr_text)
        ctype = (headers.get("content-type") or "").lower()
        if "text/html" not in ctype:
            try:
                print(f"[icap respmod] non-html content-type={headers.get('content-type')} -> 204", flush=True)
            except Exception:
                pass
            try:
                store.record_skip("non_html")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Collect the ICAP chunked body.
        body_off = offsets.get("res-body", 0)
        if body_off >= len(rest):
            # read more
            try:
                while len(rest) < body_off + 8 and len(rest) < 8 * 1024 * 1024:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
            except TimeoutError:
                try:
                    self.request.sendall(_icap_204())
                except Exception:
                    pass
                return

        body_chunked = rest[body_off:]
        # keep reading until chunked terminator seen (best-effort cap)
        try:
            while b"\r\n0\r\n\r\n" not in body_chunked and len(body_chunked) < 8 * 1024 * 1024:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                body_chunked += chunk
        except TimeoutError:
            pass

        raw_http_body, complete = _decode_icap_chunked(body_chunked)
        if not complete:
            try:
                print("[icap respmod] icap chunked incomplete -> 204", flush=True)
            except Exception:
                pass
            try:
                store.record_skip("incomplete_body")
            except Exception:
                pass
            # incomplete; do not block
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        try:
            print(f"[icap respmod] got body bytes={len(raw_http_body)}", flush=True)
        except Exception:
            pass

        enc = headers.get("content-encoding") or ""
        dec, style = _maybe_decompress(raw_http_body, enc)
        if dec is None:
            try:
                print(f"[icap respmod] unsupported/invalid content-encoding={enc!r} -> 204", flush=True)
            except Exception:
                pass
            try:
                store.record_skip("unsupported_encoding")
            except Exception:
                pass
            # Unsupported or invalid encoding (e.g. br). Skip.
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        # Determine charset (best-effort) and decode.
        charset = "utf-8"
        m = re.search(r"charset\s*=\s*([A-Za-z0-9._-]+)", headers.get("content-type") or "", re.I)
        if m:
            charset = m.group(1).strip().lower() or "utf-8"

        try:
            html_text = dec.decode(charset, errors="replace")
        except Exception:
            html_text = dec.decode("utf-8", errors="replace")

        new_html, added = _inject_preloads_into_html(html_text)
        if not new_html:
            try:
                print("[icap respmod] no </head> or no <img src> -> 204", flush=True)
            except Exception:
                pass
            try:
                store.record_skip("no_head_or_imgs")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass
            return

        new_plain = new_html.encode(charset, errors="replace")
        new_body, out_enc = _recompress(new_plain, style)

        # Rebuild HTTP response headers: keep status line and most headers.
        # Remove hop-by-hop/size headers, then add updated Content-Length.
        hdr_lines = (res_hdr_text or "").split("\r\n")
        while hdr_lines and hdr_lines[-1] == "":
            hdr_lines = hdr_lines[:-1]

        hdr_lines = _remove_headers(
            hdr_lines,
            {"content-length", "transfer-encoding", "content-encoding", "connection", "keep-alive", "proxy-connection"},
        )

        # Ensure status line still first.
        if not hdr_lines or not hdr_lines[0].startswith("HTTP/"):
            hdr_lines = [status_line] + hdr_lines[1:]

        if out_enc:
            hdr_lines.append(f"Content-Encoding: {out_enc}")
        hdr_lines.append(f"Content-Length: {len(new_body)}")
        hdr_lines.append("Connection: close")
        http_hdr_out = "\r\n".join(hdr_lines) + "\r\n\r\n"

        try:
            try:
                print(f"[icap respmod] injected, out_bytes={len(new_body)}, out_enc={out_enc or 'identity'}", flush=True)
            except Exception:
                pass
            try:
                store.record_injected(links_added=int(added or 0))
            except Exception:
                pass
            self.request.sendall(_build_icap_resp_with_http(http_hdr_out, new_body))
        except Exception:
            try:
                store.record_failure("send_modified_response_failed")
            except Exception:
                pass
            try:
                self.request.sendall(_icap_204())
            except Exception:
                pass


class AdblockEngine:
    def __init__(self) -> None:
        self.store = get_adblock_store()
        self.store.init_db()

        self._lock = threading.Lock()
        self._ruleset = _Ruleset()
        self._stop = False

        # Bounded LRU cache for URL decisions to reduce per-request rule eval cost.
        # Maps cache_key -> (ts, matched_list_key_or_empty)
        self._cache_lock = threading.Lock()
        self._decision_cache: "OrderedDict[str, Tuple[int, str]]" = OrderedDict()
        settings = self.store.get_settings()
        self._enabled = bool(settings.get("enabled"))
        self._decision_cache_ttl = int(settings.get("cache_ttl") or 0)
        self._decision_cache_max = int(settings.get("cache_max") or 0)

        # Track cache effectiveness without per-request SQLite writes.
        self._cache_stats_lock = threading.Lock()
        self._pending_cache_stats: Counter[str] = Counter()

        # Batch block-stat writes to avoid per-request SQLite work.
        self._stats_lock = threading.Lock()
        self._pending_blocks: Counter[str] = Counter()

        if AdblockRules is None:
            raise RuntimeError("adblockparser is not installed")

        # Log once at startup; useful when tuning performance.
        try:
            print(f"[adblock] RE2 enabled: {_HAS_RE2}", flush=True)
        except Exception:
            pass

    def stop(self) -> None:
        self._stop = True

    def start_background(self) -> None:
        t = threading.Thread(target=self._loop, name="adblock-updater", daemon=True)
        t.start()

        s = threading.Thread(target=self._stats_loop, name="adblock-stats", daemon=True)
        s.start()

    def _stats_loop(self) -> None:
        # Flush frequently to keep UI stats reasonably fresh, but avoid hammering SQLite.
        while not self._stop:
            try:
                self._flush_pending_blocks()
            except Exception:
                pass
            try:
                self._flush_cache_stats(force_flush=False)
            except Exception:
                pass
            time.sleep(2)

        try:
            self._flush_pending_blocks()
        except Exception:
            pass
        try:
            self._flush_cache_stats(force_flush=True)
        except Exception:
            pass

    def _flush_pending_blocks(self) -> None:
        with self._stats_lock:
            if not self._pending_blocks:
                return
            counts = dict(self._pending_blocks)
            self._pending_blocks.clear()

        try:
            self.store.record_blocks_bulk(counts)
        except Exception:
            # Best-effort: if we fail to flush, re-add counts so they aren't lost.
            with self._stats_lock:
                self._pending_blocks.update(counts)

    def _loop(self) -> None:
        last_refresh_req = 0
        last_cache_flush_req = 0
        while not self._stop:
            try:
                refresh_req = self.store.get_refresh_requested()
                force = refresh_req > last_refresh_req
                if force:
                    last_refresh_req = refresh_req

                cache_flush_req = self.store.get_cache_flush_requested()
                if cache_flush_req > last_cache_flush_req:
                    last_cache_flush_req = cache_flush_req
                    try:
                        with self._cache_lock:
                            evicted = len(self._decision_cache)
                            self._decision_cache.clear()
                        self._record_cache_stat("evictions", evicted)
                        self._flush_cache_stats(force_flush=True)
                    except Exception:
                        pass

                # Download updates for enabled lists if due.
                any_updated = False
                for st in self.store.list_statuses():
                    if self.store.update_one(st.key, force=force):
                        any_updated = True

                # Rebuild rules if settings changed, or after refresh.
                current_version = self.store.get_settings_version()
                if force or any_updated or current_version != self._ruleset.version:
                    new_ruleset = self._build_ruleset(current_version)
                    try:
                        settings = self.store.get_settings()
                    except Exception:
                        settings = {"enabled": True, "cache_ttl": 0, "cache_max": 0}

                    with self._lock:
                        self._ruleset = new_ruleset
                        self._enabled = bool(settings.get("enabled"))
                        self._decision_cache_ttl = int(settings.get("cache_ttl") or 0)
                        self._decision_cache_max = int(settings.get("cache_max") or 0)

                    # Clear cache outside the ruleset lock to avoid lock-order deadlocks.
                    try:
                        with self._cache_lock:
                            self._decision_cache.clear()
                    except Exception:
                        pass

            except Exception:
                pass

            time.sleep(30)

    def _build_ruleset(self, version: int) -> _Ruleset:
        rs = _Ruleset()
        rs.version = version

        statuses = self.store.list_statuses()

        # First pass: collect rule objects + rich candidate anchors.
        tmp: List[Tuple[str, object, bool, Optional[bool], Set[str], Set[str]]] = []
        host_df: Counter[str] = Counter()
        token_df: Counter[str] = Counter()

        for st in statuses:
            rs.enabled[st.key] = st.enabled
            if not st.enabled:
                continue
            path = self.store.list_path(st.key)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = [ln.strip("\r\n") for ln in f.readlines()]
                ruleset = AdblockRules(lines, use_re2=_HAS_RE2)  # type: ignore
                for rule in getattr(ruleset, "rules", []) or []:
                    try:
                        if getattr(rule, "is_comment", False):
                            continue
                        if not getattr(rule, "matching_supported", True):
                            continue
                        if getattr(rule, "is_html_rule", False):
                            continue

                        tp_opt: Optional[bool] = None
                        try:
                            opts = getattr(rule, "options", {}) or {}
                            if "third-party" in opts:
                                tp_opt = bool(opts.get("third-party"))
                        except Exception:
                            tp_opt = None

                        host_cand, token_cand = _extract_rule_keys(rule)
                        is_exc = bool(getattr(rule, "is_exception", False))
                        tmp.append((st.key, rule, is_exc, tp_opt, host_cand, token_cand))

                        for hk in set(host_cand):
                            host_df[hk] += 1
                        for tk in set(token_cand):
                            token_df[tk] += 1
                    except Exception:
                        continue
            except Exception:
                continue

        # Second pass: choose the rarest anchors per rule to minimize candidate fan-out.
        entries: List[_RuleEntry] = []
        order = 0
        for list_key, rule, is_exc, tp_opt, host_cand, token_cand in tmp:
            host_sorted = sorted(host_cand, key=lambda h: (host_df.get(h, 0), -len(h)))
            host_keys = tuple(host_sorted[:2])

            token_sorted = sorted(token_cand, key=lambda t: (token_df.get(t, 0), -len(t)))
            token_keys = tuple(token_sorted[:_MAX_TOKENS_PER_RULE])

            entries.append(
                _RuleEntry(
                    order=order,
                    list_key=list_key,
                    rule=rule,
                    is_exception=is_exc,
                    host_keys=host_keys,
                    token_keys=token_keys,
                    third_party_opt=tp_opt,
                )
            )
            order += 1

        try:
            rs.matcher = _CandidateMatcher(entries)
        except Exception:
            rs.matcher = _CandidateMatcher([])
        return rs

    def should_block(self, url: str, *, document_host: str = "", third_party: Optional[bool] = None) -> Optional[str]:
        # Return list_key that matched, else None.
        if not self._enabled:
            return None

        now_ts = _now()
        host = _host_from_url(url)

        doc = (document_host or "").strip().lower().rstrip(".")
        if not doc:
            doc = host

        tp = "u"
        if third_party is True:
            tp = "1"
        elif third_party is False:
            tp = "0"

        cache_key = f"{url}|d={doc}|tp={tp}"
        if self._decision_cache_ttl > 0 and self._decision_cache_max > 0:
            try:
                with self._cache_lock:
                    cached = self._decision_cache.get(cache_key)
                    if cached is not None:
                        ts, val = cached
                        if (now_ts - ts) <= self._decision_cache_ttl:
                            # LRU bump
                            self._decision_cache.move_to_end(cache_key)
                            self._record_cache_stat("hits", 1)
                            return val or None
                        # Expired
                        self._decision_cache.pop(cache_key, None)
                        self._record_cache_stat("evictions", 1)
            except Exception:
                pass

        if self._decision_cache_ttl > 0 and self._decision_cache_max > 0:
            self._record_cache_stat("misses", 1)

        with self._lock:
            matcher = self._ruleset.matcher

        blocked_by: Optional[str] = None
        try:
            if matcher is not None:
                blocked_by = matcher.match(url, document_host=doc, third_party=third_party)
        except Exception:
            blocked_by = None

        if blocked_by:
            if self._decision_cache_ttl > 0 and self._decision_cache_max > 0:
                try:
                    with self._cache_lock:
                        self._decision_cache[cache_key] = (now_ts, blocked_by)
                        self._decision_cache.move_to_end(cache_key)
                        while len(self._decision_cache) > self._decision_cache_max:
                            self._decision_cache.popitem(last=False)
                            self._record_cache_stat("evictions", 1)
                except Exception:
                    pass
            return blocked_by
        if self._decision_cache_ttl > 0 and self._decision_cache_max > 0:
            try:
                with self._cache_lock:
                    self._decision_cache[cache_key] = (now_ts, "")
                    self._decision_cache.move_to_end(cache_key)
                    while len(self._decision_cache) > self._decision_cache_max:
                        self._decision_cache.popitem(last=False)
                        self._record_cache_stat("evictions", 1)
            except Exception:
                pass
        return None

    def record(self, list_key: str) -> None:
        # Keep request threads fast: just increment in-memory and let the
        # background flusher persist to SQLite.
        if not list_key:
            return
        try:
            with self._stats_lock:
                self._pending_blocks[list_key] += 1
        except Exception:
            pass

    def _record_cache_stat(self, key: str, delta: int) -> None:
        if delta <= 0:
            return
        try:
            with self._cache_stats_lock:
                self._pending_cache_stats[key] += int(delta)
        except Exception:
            pass

    def _flush_cache_stats(self, force_flush: bool = False) -> None:
        hits = misses = evictions = 0
        try:
            with self._cache_stats_lock:
                if not self._pending_cache_stats and not force_flush:
                    return
                hits = int(self._pending_cache_stats.get("hits", 0))
                misses = int(self._pending_cache_stats.get("misses", 0))
                evictions = int(self._pending_cache_stats.get("evictions", 0))
                self._pending_cache_stats.clear()
        except Exception:
            return

        size = None
        try:
            with self._cache_lock:
                size = len(self._decision_cache)
        except Exception:
            size = None

        try:
            self.store.record_cache_stats(
                hits=hits,
                misses=misses,
                evictions=evictions,
                size=size,
            )
        except Exception:
            pass


class IcapServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, engine: AdblockEngine):
        super().__init__(server_address, handler_class)
        self.engine = engine


def main() -> None:
    engine = AdblockEngine()
    engine.start_background()

    host = (os.environ.get("ICAP_BIND") or "127.0.0.1").strip()
    port = int((os.environ.get("ICAP_PORT") or "1344").strip())

    with IcapServer((host, port), IcapHandler, engine) as srv:
        srv.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
