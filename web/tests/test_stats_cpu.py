from __future__ import annotations

import pytest
from services import stats


def _get_cpu_utilization(monkeypatch, samples: list[str]) -> float | None:
    sample_iter = iter(samples)
    monkeypatch.setattr(stats, "_read_text", lambda _path: next(sample_iter))
    monkeypatch.setattr(stats.time, "sleep", lambda _seconds: None)
    return stats.get_cpu_utilization_percent()


@pytest.mark.parametrize(
    ("samples", "expected"),
    [
        (
            [
                "cpu 100 0 50 100 10 0 0 0 0 0\n",
                "cpu 120 0 60 150 10 0 0 0 0 0\n",
            ],
            37.5,
        ),
        (
            [
                "cpu 100 0 50 100 10 0 0 0 0 0\n",
                "cpu 150 0 50 100 10 0 0 0 0 0\n",
            ],
            100.0,
        ),
        (
            [
                "cpu 100 0 50 100 10 0 0 0 0 0\n",
                "cpu 100 0 50 150 10 0 0 0 0 0\n",
            ],
            0.0,
        ),
    ],
)
def test_cpu_utilization_preserves_valid_delta_boundaries(
    monkeypatch,
    samples: list[str],
    expected: float,
) -> None:
    assert _get_cpu_utilization(monkeypatch, samples) == pytest.approx(expected)


@pytest.mark.parametrize(
    "samples",
    [
        [
            "cpu 100 0 50 100 20 0 0 0 0 0\n",
            "cpu 150 0 50 100 10 0 0 0 0 0\n",
        ],
        [
            "cpu 100 0 100 100 0 0 0 0 0 0\n",
            "cpu 50 0 100 200 0 0 0 0 0 0\n",
        ],
    ],
)
def test_cpu_utilization_rejects_inconsistent_regressed_counters(
    monkeypatch,
    samples: list[str],
) -> None:
    assert _get_cpu_utilization(monkeypatch, samples) is None
