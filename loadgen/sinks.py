"""Where the generated events go: a Redis stream (the real target), a JSONL file, or nowhere (speed test)."""
import json
import time
from pathlib import Path


def encode(event: dict) -> dict:
    """The stream message: the whole event as JSON in `data`, plus what the consumers need without parsing it.
    Agree the final message format with Alaa (A1/A2) and change it only here."""
    return {"event_id": event["event_id"], "sent_at_ms": str(int(time.time() * 1000)), "data": json.dumps(event, separators=(",", ":"))}


class RedisSink:
    def __init__(self, client, stream: str = "events", maxlen: int | None = None, batch: int = 500):
        self.client, self.stream, self.maxlen, self.batch = client, stream, maxlen, batch

    def write(self, events: list[dict]) -> int:
        for i in range(0, len(events), self.batch):
            pipe = self.client.pipeline(transaction=False)
            for event in events[i:i + self.batch]:
                pipe.xadd(self.stream, encode(event), maxlen=self.maxlen, approximate=self.maxlen is not None)
            pipe.execute()
        return len(events)

    def close(self) -> None:
        pass


class JsonlSink:
    def __init__(self, path: str | Path):
        self.file = open(path, "w", encoding="utf-8")

    def write(self, events: list[dict]) -> int:
        for event in events:
            self.file.write(json.dumps(event) + "\n")
        return len(events)

    def close(self) -> None:
        self.file.close()


class NullSink:
    def write(self, events: list[dict]) -> int:
        return len(events)

    def close(self) -> None:
        pass


def send(factory, sink, rate: float = 0, chunk: int = 2_000) -> tuple[int, float]:
    """Write every event of the factory to the sink. rate = events per second (0 = as fast as possible)."""
    sent, begin = 0, time.monotonic()
    for events in factory.chunks(chunk):
        step = max(1, int(rate // 20)) if rate else len(events)       # about 20 small bursts per second
        for i in range(0, len(events), step):
            part = events[i:i + step]
            sink.write(part)
            sent += len(part)
            if rate:
                ahead = sent / rate - (time.monotonic() - begin)
                if ahead > 0:
                    time.sleep(ahead)
    return sent, time.monotonic() - begin
