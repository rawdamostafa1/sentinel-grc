"""A small reference consumer for the events stream (consumer group, acknowledgements, dead-letter stream).

It stands in for the detector while the real pipeline is not there yet, and it measures what a consumer sees:
how many events were processed, how long each took from being sent to being read (end-to-end latency),
duplicates, dead letters and what is left pending. To test Alaa's real consumers instead, run only the generator.
"""
import json
import time

from .metrics import Report


def ensure_group(client, stream: str, group: str) -> None:
    try:
        client.xgroup_create(stream, group, id="0", mkstream=True)
    except Exception as exc:                          # the group already exists
        if "BUSYGROUP" not in str(exc):
            raise


def consume(client, stream: str = "events", group: str = "detector", name: str = "worker-1", expected: int | None = None,
            idle_seconds: float = 2.0, batch: int = 500, report: Report | None = None, latencies: list | None = None,
            seen: set | None = None, dead_stream: str | None = None) -> Report:
    """Read until `expected` events were processed or nothing new arrived for idle_seconds."""
    report = report or Report()
    latencies = latencies if latencies is not None else []
    seen = seen if seen is not None else set()
    dead_stream = dead_stream or f"{stream}:dead"
    ensure_group(client, stream, group)
    begin, last_data = time.monotonic(), time.monotonic()
    while True:
        batches = client.xreadgroup(group, name, {stream: ">"}, count=batch, block=200)
        if not batches:
            if time.monotonic() - last_data > idle_seconds or (expected is not None and report.processed >= expected):
                break
            continue
        last_data = time.monotonic()
        ids = []
        now_ms = time.time() * 1000
        for _stream, messages in batches:
            for message_id, fields in messages:
                ids.append(message_id)
                try:
                    event = json.loads(fields["data"])
                    event_id = event["event_id"]
                except (KeyError, ValueError, TypeError):
                    client.xadd(dead_stream, {"reason": "unparseable", "message_id": message_id})
                    report.dead_letter += 1
                    continue
                if event_id in seen:
                    report.duplicates += 1
                    continue
                seen.add(event_id)
                report.processed += 1
                latencies.append(now_ms - int(fields["sent_at_ms"]))
        client.xack(stream, group, *ids)
    report.process_seconds = max(report.process_seconds, time.monotonic() - begin)
    return report


def pending(client, stream: str, group: str) -> int:
    info = client.xpending(stream, group)
    return int(info["pending"] if isinstance(info, dict) else info[0])
