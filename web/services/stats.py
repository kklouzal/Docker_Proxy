from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
import csv
import io
from dataclasses import dataclass
from typing import Any, Dict, Optional

from services.logutil import log_exception_throttled


logger = logging.getLogger(__name__)


_CACHE_LOCK = threading.Lock()
_CACHE_DIR_SIZE_INFLIGHT = False
_CACHE_DIR_SIZE_TS = 0.0
_CACHE_DIR_SIZE_VALUE: Optional[int] = None

_CACHE_DISK_USAGE_INFLIGHT = False
_CACHE_DISK_USAGE_TS = 0.0
_CACHE_DISK_USAGE_VALUE: Optional[DiskUsage] = None

_CACHE_HIT_RATE_INFLIGHT = False
_CACHE_HIT_RATE_TS = 0.0
_CACHE_HIT_RATE_VALUE: Optional[Dict[str, Optional[float]]] = None
_CACHE_HIT_RATE_SOURCE_VALUE: str = ""

_CACHE_CPU_INFLIGHT = False
_CACHE_CPU_TS = 0.0
_CACHE_CPU_VALUE: Optional[Dict[str, Any]] = None


@dataclass
class DiskUsage:
    total_bytes: int
    used_bytes: int
    free_bytes: int


def _env_flag(name: str, default: str = "0") -> bool:
    v = (os.environ.get(name, default) or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _format_bytes(num_bytes: Optional[int]) -> str:
    if num_bytes is None:
        return "n/a"
    step = 1024.0
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(num_bytes)
    for unit in units:
        if value < step:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= step
    return f"{value:.1f} PiB"


def _safe_pct(numer: Optional[float], denom: Optional[float]) -> Optional[float]:
    if numer is None or denom is None or denom == 0:
        return None
    return 100.0 * float(numer) / float(denom)


def get_disk_usage(path: str) -> Optional[DiskUsage]:
    try:
        du = shutil.disk_usage(path)
        return DiskUsage(total_bytes=du.total, used_bytes=du.used, free_bytes=du.free)
    except Exception:
        return None


def get_directory_size_bytes(path: str) -> Optional[int]:
    try:
        total = 0
        for root, _, files in os.walk(path):
            for name in files:
                file_path = os.path.join(root, name)
                try:
                    total += os.path.getsize(file_path)
                except OSError:
                    continue
        return total
    except Exception:
        return None


def get_meminfo() -> Dict[str, Optional[int]]:
    # Returns bytes for total/available
    out: Dict[str, Optional[int]] = {"total": None, "available": None}
    try:
        data = _read_text("/proc/meminfo")
        total_kib = re.search(r"^MemTotal:\s+(\d+)\s+kB", data, re.M)
        avail_kib = re.search(r"^MemAvailable:\s+(\d+)\s+kB", data, re.M)
        if total_kib:
            out["total"] = int(total_kib.group(1)) * 1024
        if avail_kib:
            out["available"] = int(avail_kib.group(1)) * 1024
    except Exception:
        log_exception_throttled(
            logger,
            "stats.meminfo",
            interval_seconds=300.0,
            message="Failed to read /proc/meminfo",
        )
    return out


def get_cpu_utilization_percent(sample_seconds: float = 0.15) -> Optional[float]:
    # Best-effort CPU utilization across all cores using /proc/stat.
    # Returns None if not available.
    def read() -> Optional[Dict[str, int]]:
        try:
            line = _read_text("/proc/stat").splitlines()[0]
            parts = line.split()
            if parts[0] != "cpu":
                return None
            values = list(map(int, parts[1:]))
            # user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
            while len(values) < 10:
                values.append(0)
            user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice = values[:10]
            idle_all = idle + iowait
            non_idle = user + nice + system + irq + softirq + steal
            total = idle_all + non_idle
            return {"total": total, "idle": idle_all}
        except Exception:
            return None

    s1 = read()
    if not s1:
        return None
    time.sleep(max(sample_seconds, 0.05))
    s2 = read()
    if not s2:
        return None

    total_delta = s2["total"] - s1["total"]
    idle_delta = s2["idle"] - s1["idle"]
    if total_delta <= 0:
        return None
    return (1.0 - (idle_delta / total_delta)) * 100.0


def get_loadavg() -> Optional[Dict[str, float]]:
    try:
        parts = _read_text("/proc/loadavg").split()
        return {"1m": float(parts[0]), "5m": float(parts[1]), "15m": float(parts[2])}
    except Exception:
        return None


def _run(cmd: list[str], timeout: float = 2.0, env: Optional[Dict[str, str]] = None) -> Optional[str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if p.returncode != 0:
            return None
        return p.stdout
    except Exception:
        return None


def get_squid_mgr_text(section: str, host: str = "127.0.0.1", port: int = 3128) -> Optional[str]:
    # Opt-in: cachemgr polling can be surprisingly expensive and has been observed
    # to trigger forwarding-loop warnings and Squid instability in some setups.
    # Default is disabled; enable explicitly if you want cachemgr-based stats.
    if not _env_flag("STATS_USE_CACHEMGR", "0"):
        return None

    # Requires squidclient in the image and cachemgr allowed for localhost.
    if shutil.which("squidclient") is None:
        return None

    # Avoid accidental self-proxying if the container has proxy env vars set.
    safe_env = dict(os.environ)
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        safe_env.pop(k, None)
    existing_no_proxy = safe_env.get("NO_PROXY") or safe_env.get("no_proxy") or ""
    additions = ["127.0.0.1", "localhost", "::1"]
    merged = ",".join([p for p in (existing_no_proxy.split(",") if existing_no_proxy else []) if p])
    for a in additions:
        if a not in merged.split(","):
            merged = f"{merged},{a}" if merged else a
    safe_env["NO_PROXY"] = merged
    safe_env["no_proxy"] = merged

    return _run(["squidclient", "-h", host, "-p", str(port), f"mgr:{section}"], env=safe_env)


def parse_access_log_hit_rate(access_log_path: str = "/var/log/squid/access.log", max_lines: int = 5000) -> Dict[str, Optional[float]]:
    # Best-effort rolling hit rate from recent access.log lines.
    # Squid default log format typically contains:
    #   ts elapsed client result_code/status bytes method url ...
    # where result_code looks like TCP_HIT/200, TCP_MISS/200, etc.
    hits = 0
    total = 0
    hit_bytes = 0
    total_bytes = 0

    try:
        if not os.path.exists(access_log_path):
            return {"request_hit_ratio": None, "byte_hit_ratio": None}

        # Read last ~max_lines lines without external dependencies.
        with open(access_log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            # Heuristic: assume avg 200 bytes/line
            read_size = min(size, max_lines * 220)
            f.seek(-read_size, os.SEEK_END)
            chunk = f.read().decode("utf-8", errors="replace")
        lines = chunk.splitlines()[-max_lines:]

        for line in lines:
            s = (line or "").strip("\r\n")
            if not s:
                continue

            # New structured TSV format. Squid may emit "\\t" literally.
            if "\t" in s or "\\t" in s:
                if "\\t" in s and "\t" not in s:
                    s = s.replace("\\t", "\t")
                try:
                    row = next(csv.reader(io.StringIO(s), delimiter="\t", quotechar='"'))
                except Exception:
                    continue
                if len(row) < 7:
                    continue
                result = row[5]
                bytes_str = row[6]
            else:
                parts = s.split()
                if len(parts) < 5:
                    continue
                result = parts[3]  # e.g. TCP_HIT/200
                bytes_str = parts[4]

            total += 1

            try:
                b = int(bytes_str)
            except ValueError:
                b = 0
            total_bytes += max(b, 0)

            # Treat HIT variants as hit; everything else as miss.
            # Examples: TCP_HIT, TCP_MEM_HIT, TCP_IMS_HIT, TCP_REFRESH_HIT
            if "HIT" in result and not result.startswith("TCP_DENIED"):
                hits += 1
                hit_bytes += max(b, 0)

        return {
            "request_hit_ratio": (hits / total * 100.0) if total else None,
            "byte_hit_ratio": (hit_bytes / total_bytes * 100.0) if total_bytes else None,
        }
    except Exception:
        return {"request_hit_ratio": None, "byte_hit_ratio": None}


def parse_squid_hit_rate(mgr_5min: str) -> Dict[str, Optional[float]]:
    # Best-effort extraction; varies across Squid builds.
    # We'll return request hit ratios if present.
    out: Dict[str, Optional[float]] = {
        "request_hit_ratio": None,
        "byte_hit_ratio": None,
    }

    # Common patterns found in cachemgr reports.
    # Example candidates:
    #   "Request Hit Ratios: 5min: 12.3%" or
    #   "Request Hit Ratios: 5min: 12.3% 60min: ..."
    m = re.search(r"Request Hit Ratios:\s*5min:\s*([0-9.]+)%", mgr_5min)
    if m:
        out["request_hit_ratio"] = float(m.group(1))

    m = re.search(r"Byte Hit Ratios:\s*5min:\s*([0-9.]+)%", mgr_5min)
    if m:
        out["byte_hit_ratio"] = float(m.group(1))

    return out


def get_stats() -> Dict[str, Any]:
    # These values can be expensive to compute (filesystem walks, subprocesses).
    # The UI and sampler don't need sub-second freshness, so we cache them.
    dir_size_ttl = max(5, int(os.environ.get("STATS_CACHE_DIR_SIZE_TTL_SECONDS", "60")))
    disk_usage_ttl = max(2, int(os.environ.get("STATS_CACHE_DISK_USAGE_TTL_SECONDS", "15")))
    hit_rate_ttl = max(1, int(os.environ.get("STATS_CACHE_HIT_RATE_TTL_SECONDS", "5")))
    cpu_ttl = max(1, int(os.environ.get("STATS_CACHE_CPU_TTL_SECONDS", "2")))

    try:
        cpu_sample_seconds = float(os.environ.get("STATS_CPU_SAMPLE_SECONDS", "0.15"))
    except Exception:
        cpu_sample_seconds = 0.15

    mem = get_meminfo()
    used_mem = None
    if mem.get("total") is not None and mem.get("available") is not None:
        used_mem = int(mem["total"] - mem["available"])  # type: ignore[operator]

    cache_dir = "/var/spool/squid"
    now_mono = time.monotonic()

    def _maybe_get_disk_usage() -> Optional[DiskUsage]:
        global _CACHE_DISK_USAGE_INFLIGHT, _CACHE_DISK_USAGE_TS, _CACHE_DISK_USAGE_VALUE
        with _CACHE_LOCK:
            cached = _CACHE_DISK_USAGE_VALUE
            age_ok = (now_mono - _CACHE_DISK_USAGE_TS) < float(disk_usage_ttl)
            inflight = _CACHE_DISK_USAGE_INFLIGHT
        if cached is not None and age_ok:
            return cached
        if inflight:
            return cached

        with _CACHE_LOCK:
            if _CACHE_DISK_USAGE_INFLIGHT:
                return _CACHE_DISK_USAGE_VALUE
            _CACHE_DISK_USAGE_INFLIGHT = True
        try:
            value = get_disk_usage(cache_dir)
            with _CACHE_LOCK:
                _CACHE_DISK_USAGE_VALUE = value
                _CACHE_DISK_USAGE_TS = now_mono
            return value
        finally:
            with _CACHE_LOCK:
                _CACHE_DISK_USAGE_INFLIGHT = False

    def _maybe_get_dir_size() -> Optional[int]:
        global _CACHE_DIR_SIZE_INFLIGHT, _CACHE_DIR_SIZE_TS, _CACHE_DIR_SIZE_VALUE
        with _CACHE_LOCK:
            cached = _CACHE_DIR_SIZE_VALUE
            age_ok = (now_mono - _CACHE_DIR_SIZE_TS) < float(dir_size_ttl)
            inflight = _CACHE_DIR_SIZE_INFLIGHT
        if cached is not None and age_ok:
            return cached
        if inflight:
            return cached

        with _CACHE_LOCK:
            if _CACHE_DIR_SIZE_INFLIGHT:
                return _CACHE_DIR_SIZE_VALUE
            _CACHE_DIR_SIZE_INFLIGHT = True
        try:
            value = get_directory_size_bytes(cache_dir)
            with _CACHE_LOCK:
                _CACHE_DIR_SIZE_VALUE = value
                _CACHE_DIR_SIZE_TS = now_mono
            return value
        finally:
            with _CACHE_LOCK:
                _CACHE_DIR_SIZE_INFLIGHT = False

    cache_disk = _maybe_get_disk_usage()
    cache_used_dir = _maybe_get_dir_size()

    def _maybe_get_hit_rate() -> tuple[Dict[str, Optional[float]], str, bool]:
        global _CACHE_HIT_RATE_INFLIGHT, _CACHE_HIT_RATE_TS, _CACHE_HIT_RATE_VALUE, _CACHE_HIT_RATE_SOURCE_VALUE
        with _CACHE_LOCK:
            cached = _CACHE_HIT_RATE_VALUE
            cached_source = _CACHE_HIT_RATE_SOURCE_VALUE
            age_ok = (now_mono - _CACHE_HIT_RATE_TS) < float(hit_rate_ttl)
            inflight = _CACHE_HIT_RATE_INFLIGHT
        if cached is not None and age_ok:
            return cached, cached_source, True
        if inflight and cached is not None:
            return cached, cached_source, True

        with _CACHE_LOCK:
            if _CACHE_HIT_RATE_INFLIGHT:
                if _CACHE_HIT_RATE_VALUE is not None:
                    return _CACHE_HIT_RATE_VALUE, _CACHE_HIT_RATE_SOURCE_VALUE, True
            _CACHE_HIT_RATE_INFLIGHT = True

        try:
            mgr_5min = get_squid_mgr_text("5min")
            mgr_info = None
            if mgr_5min is None:
                mgr_info = get_squid_mgr_text("info")
            if mgr_5min:
                value = parse_squid_hit_rate(mgr_5min)
                src = "cachemgr"
            else:
                value = parse_access_log_hit_rate()
                src = "access.log"

            mgr_available = mgr_5min is not None or mgr_info is not None
            with _CACHE_LOCK:
                _CACHE_HIT_RATE_VALUE = value
                _CACHE_HIT_RATE_SOURCE_VALUE = src
                _CACHE_HIT_RATE_TS = now_mono
            return value, src, mgr_available
        finally:
            with _CACHE_LOCK:
                _CACHE_HIT_RATE_INFLIGHT = False

    hit, hit_source, mgr_available = _maybe_get_hit_rate()

    def _maybe_get_cpu() -> Dict[str, Any]:
        global _CACHE_CPU_INFLIGHT, _CACHE_CPU_TS, _CACHE_CPU_VALUE
        with _CACHE_LOCK:
            cached = _CACHE_CPU_VALUE
            age_ok = (now_mono - _CACHE_CPU_TS) < float(cpu_ttl)
            inflight = _CACHE_CPU_INFLIGHT
        if cached is not None and age_ok:
            return cached
        if inflight and cached is not None:
            return cached

        with _CACHE_LOCK:
            if _CACHE_CPU_INFLIGHT and _CACHE_CPU_VALUE is not None:
                return _CACHE_CPU_VALUE
            _CACHE_CPU_INFLIGHT = True

        try:
            value: Dict[str, Any] = {
                "util_percent": get_cpu_utilization_percent(sample_seconds=cpu_sample_seconds),
                "loadavg": get_loadavg(),
            }
            with _CACHE_LOCK:
                _CACHE_CPU_VALUE = value
                _CACHE_CPU_TS = time.monotonic()
            return value
        finally:
            with _CACHE_LOCK:
                _CACHE_CPU_INFLIGHT = False

    cpu = _maybe_get_cpu()

    return {
        "cpu": {
            "util_percent": cpu.get("util_percent"),
            "loadavg": cpu.get("loadavg"),
        },
        "memory": {
            "total_bytes": mem.get("total"),
            "available_bytes": mem.get("available"),
            "used_bytes": used_mem,
            "used_percent": _safe_pct(used_mem, mem.get("total")),
        },
        "storage": {
            "cache_path": cache_dir,
            "cache_dir_size_bytes": cache_used_dir,
            "cache_fs_total_bytes": cache_disk.total_bytes if cache_disk else None,
            "cache_fs_used_bytes": cache_disk.used_bytes if cache_disk else None,
            "cache_fs_free_bytes": cache_disk.free_bytes if cache_disk else None,
            "cache_dir_size_human": _format_bytes(cache_used_dir),
            "cache_fs_total_human": _format_bytes(cache_disk.total_bytes if cache_disk else None),
            "cache_fs_used_human": _format_bytes(cache_disk.used_bytes if cache_disk else None),
            "cache_fs_free_human": _format_bytes(cache_disk.free_bytes if cache_disk else None),
        },
        "squid": {
            "hit_rate": hit,
            "mgr_available": mgr_available,
            "hit_rate_source": hit_source,
        },
    }
