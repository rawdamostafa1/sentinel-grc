"""Numbers and the report for one stress run."""
import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def percentile(sorted_values: list[float], p: float) -> float | None:
    """Nearest-rank percentile of an already sorted list. None for an empty list."""
    if not sorted_values:
        return None
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


@dataclass
class Report:
    sent: int = 0
    generated_seconds: float = 0.0
    send_seconds: float = 0.0
    processed: int = 0                 # distinct events the consumers read and acknowledged
    duplicates: int = 0                # delivered more than once
    dead_letter: int = 0               # could not be parsed and went to the dead-letter stream
    lost: int = 0                      # sent but never processed
    process_seconds: float = 0.0
    pending_at_end: int = 0            # delivered but never acknowledged
    stream_length: int = 0
    latency_ms: dict = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    def finish(self, latencies: list[float]) -> "Report":
        ordered = sorted(latencies)
        pick = lambda v: None if v is None else round(v, 1)
        self.latency_ms = {f"p{p}": pick(percentile(ordered, p)) for p in (50, 95, 99)} | {"max": pick(ordered[-1] if ordered else None)}
        self.lost = max(0, self.sent - self.processed - self.dead_letter)
        return self

    @property
    def send_rate(self) -> float:
        return round(self.sent / self.send_seconds, 1) if self.send_seconds else 0.0

    @property
    def process_rate(self) -> float:
        return round(self.processed / self.process_seconds, 1) if self.process_seconds else 0.0

    def to_dict(self) -> dict:
        return {**asdict(self), "send_rate_eps": self.send_rate, "process_rate_eps": self.process_rate}

    def to_markdown(self) -> str:
        d, lat = self.to_dict(), self.latency_ms
        rows = [("Events sent", d["sent"]), ("Send rate (events/s)", d["send_rate_eps"]),
                ("Events processed", d["processed"]), ("Process rate (events/s)", d["process_rate_eps"]),
                ("Lost", d["lost"]), ("Duplicates", d["duplicates"]), ("Dead-letter", d["dead_letter"]),
                ("Still pending (never acknowledged)", d["pending_at_end"]),
                ("End-to-end latency p50 / p95 / p99 / max (ms)", " / ".join(str(lat.get(k)) for k in ("p50", "p95", "p99", "max")))]
        table = "\n".join(f"| {name} | {value} |" for name, value in rows)
        return (f"# Stress test report\n\n| Metric | Value |\n|---|---|\n{table}\n\n"
                f"Config: `{json.dumps(self.config, default=str)}`\n\n"
                "This measures the capacity of the pipeline under synthetic load. It says nothing about detection accuracy.\n")

    def save(self, directory: str | Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        (directory / f"stress-{stamp}.json").write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")
        path = directory / f"stress-{stamp}.md"
        path.write_text(self.to_markdown(), encoding="utf-8")
        return path
