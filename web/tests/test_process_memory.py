from __future__ import annotations

from typing import TYPE_CHECKING

from proxy.process_memory import cgroup_memory, supervisor_program_memory

if TYPE_CHECKING:
    from pathlib import Path


def _process(
    proc: Path, pid: int, ppid: int, name: str, rss: int, anon: int, shmem: int = 0
) -> None:
    directory = proc / str(pid)
    directory.mkdir()
    # The command name may contain spaces and parentheses.
    (directory / "stat").write_text(
        f"{pid} ({name}) S {ppid} {pid} {pid} 0 -1\n", encoding="ascii"
    )
    (directory / "status").write_text(
        f"Name:\t{name}\nVmRSS:\t{rss} kB\nRssAnon:\t{anon} kB\n"
        f"RssFile:\t{rss - anon - shmem} kB\nRssShmem:\t{shmem} kB\n",
        encoding="ascii",
    )


def test_program_memory_sums_each_running_program_process_tree(tmp_path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    _process(proc, 1, 0, "supervisord", 25000, 16000)
    _process(proc, 10, 1, "squid", 18000, 4000, 13000)
    _process(proc, 11, 10, "squid-1) (kid", 36000, 18000, 2000)
    _process(proc, 12, 11, "ssl_crtd", 5000, 700)
    _process(proc, 20, 1, "python3", 57000, 40000)
    (proc / "self").mkdir()

    memory = supervisor_program_memory(
        {
            "squid": "squid    RUNNING   pid 10, uptime 0:01:00",
            "proxy_agent": "proxy_agent    RUNNING   pid 20, uptime 0:01:00",
            "cicap_av_1": "cicap_av_1    STARTING",
            "gone": "gone    RUNNING   pid 99, uptime 0:01:00",
        },
        proc_root=proc,
    )

    assert memory["squid"] == {
        "rss_kib": 59000,
        "rss_anon_kib": 22700,
        "rss_file_kib": 21300,
        "rss_shmem_kib": 15000,
        "processes": 3,
    }
    assert memory["proxy_agent"]["rss_anon_kib"] == 40000
    assert memory["proxy_agent"]["processes"] == 1
    assert "cicap_av_1" not in memory
    # An exited pid is reported with zero usage rather than failing health.
    assert memory["gone"]["rss_kib"] == 0


def test_cgroup_memory_reads_v2_counters(tmp_path) -> None:
    (tmp_path / "memory.current").write_text("834625536\n", encoding="ascii")
    (tmp_path / "memory.max").write_text("max\n", encoding="ascii")
    (tmp_path / "memory.stat").write_text(
        "anon 278302720\nfile 1387225088\nshmem 69083136\nactive_anon 1\n",
        encoding="ascii",
    )

    assert cgroup_memory(tmp_path) == {
        "current": 834625536,
        "anon": 278302720,
        "file": 1387225088,
        "shmem": 69083136,
    }
    assert cgroup_memory(tmp_path / "missing") == {}
