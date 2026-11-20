"""Per-supervisor-program memory accounting for proxy health.

Reads only /proc/<pid>/status (readable for every local process without
ptrace rights, unlike smaps) and the container cgroup v2 counters. RSS sums
count shared pages once per process: Squid's shared-memory page pool shows up
in every Squid kid's ``rss_shmem_kib``. The cgroup ``anon``/``shmem``/``file``
split is the authoritative container total; ``file`` is reclaimable page cache
that RouterOS and Docker include in ``memory.current``.
"""

from __future__ import annotations

import re
from pathlib import Path

_SUPERVISOR_PID_RE = re.compile(r"\bpid (\d+),")
_STATUS_FIELDS = {
    "VmRSS:": "rss_kib",
    "RssAnon:": "rss_anon_kib",
    "RssFile:": "rss_file_kib",
    "RssShmem:": "rss_shmem_kib",
}
_CGROUP_STAT_FIELDS = ("anon", "file", "shmem", "kernel", "sock")


def _parent_pids(proc_root: Path) -> dict[int, int]:
    parents: dict[int, int] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        # The command name is parenthesized and may contain spaces or ')'.
        fields = stat.rsplit(")", 1)[-1].split()
        if len(fields) > 1 and fields[1].isdigit():
            parents[int(entry.name)] = int(fields[1])
    return parents


def _process_tree(root: int, parents: dict[int, int]) -> list[int]:
    children: dict[int, list[int]] = {}
    for pid, parent in parents.items():
        children.setdefault(parent, []).append(pid)
    tree: list[int] = []
    pending = [root]
    while pending:
        pid = pending.pop()
        if pid in tree:
            continue
        tree.append(pid)
        pending.extend(children.get(pid, ()))
    return tree


def _status_kib(proc_root: Path, pid: int) -> dict[str, int]:
    totals = dict.fromkeys(_STATUS_FIELDS.values(), 0)
    try:
        text = (proc_root / str(pid) / "status").read_text(
            encoding="ascii", errors="replace"
        )
    except OSError:
        return totals
    for line in text.splitlines():
        parts = line.split()
        key = _STATUS_FIELDS.get(parts[0]) if parts else None
        if key and len(parts) > 1 and parts[1].isdigit():
            totals[key] = int(parts[1])
    return totals


def supervisor_program_memory(
    status_lines: dict[str, str],
    *,
    proc_root: str | Path = "/proc",
) -> dict[str, dict[str, int]]:
    """Sum /proc status memory for each RUNNING program's process tree."""
    root = Path(proc_root)
    try:
        parents = _parent_pids(root)
    except OSError:
        return {}
    programs: dict[str, dict[str, int]] = {}
    for name, line in sorted(status_lines.items()):
        match = _SUPERVISOR_PID_RE.search(line)
        if match is None:
            continue
        pids = _process_tree(int(match.group(1)), parents)
        totals = dict.fromkeys(_STATUS_FIELDS.values(), 0)
        for pid in pids:
            for key, value in _status_kib(root, pid).items():
                totals[key] += value
        totals["processes"] = len(pids)
        programs[name] = totals
    return programs


def cgroup_memory(cgroup_root: str | Path = "/sys/fs/cgroup") -> dict[str, int]:
    """Return cgroup v2 memory counters in bytes; empty when unavailable."""
    root = Path(cgroup_root)
    result: dict[str, int] = {}
    for name in ("memory.current", "memory.peak", "memory.high", "memory.max"):
        try:
            raw = (root / name).read_text(encoding="ascii").strip()
        except OSError:
            continue
        if raw.isdigit():
            result[name.removeprefix("memory.")] = int(raw)
    try:
        stat_text = (root / "memory.stat").read_text(encoding="ascii")
    except OSError:
        return result
    for line in stat_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in _CGROUP_STAT_FIELDS and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result
