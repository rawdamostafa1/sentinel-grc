"""One command: generate events into the stream while consumers read them, then print and save the report.

  python -m loadgen.stress --fake --count 10000                       self-test of the tooling (in-memory Redis)
  python -m loadgen.stress --redis-url redis://localhost:6379 --count 10000 --rate 1000 --consumers 2
  python -m loadgen.stress --redis-url ... --count 50000 --no-consumer   only generate, let Alaa's detector read

--fake only proves that the tooling works. The numbers that matter come from a real Redis and the real pipeline.
"""
import argparse
import threading

from .consume import consume, ensure_group, pending
from .events import EventFactory, LoadConfig
from .metrics import Report
from .sinks import RedisSink, send


def make_client(url: str | None, fake: bool):
    if fake:
        import fakeredis
        return fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)
    import redis
    return redis.Redis.from_url(url or "redis://localhost:6379", decode_responses=True)


def run(count=10_000, rate=0, seed=42, attack_ratio=0.25, stream="events", group="detector", consumers=1,
        client=None, maxlen=None, with_consumer=True, idle_seconds=2.0) -> Report:
    client = client or make_client(None, True)
    config = LoadConfig(count=count, seed=seed, attack_ratio=attack_ratio)
    report = Report(config={"count": count, "rate": rate, "seed": seed, "attack_ratio": attack_ratio, "stream": stream,
                            "consumers": consumers if with_consumer else 0})
    latencies, seen, lock = [], set(), threading.Lock()
    threads, parts = [], []
    if with_consumer:
        ensure_group(client, stream, group)
        for n in range(consumers):
            part = Report()
            parts.append(part)
            threads.append(threading.Thread(target=lambda p=part, n=n: consume(
                client, stream, group, f"worker-{n + 1}", expected=count, idle_seconds=idle_seconds, report=p,
                latencies=latencies, seen=seen), daemon=True))
        for t in threads:
            t.start()
    report.sent, report.send_seconds = send(EventFactory(config), RedisSink(client, stream, maxlen), rate)
    for t in threads:
        t.join()
    report.processed = len(seen)
    report.duplicates = sum(p.duplicates for p in parts)
    report.dead_letter = sum(p.dead_letter for p in parts)
    report.process_seconds = max((p.process_seconds for p in parts), default=0.0)
    report.stream_length = client.xlen(stream)
    report.pending_at_end = pending(client, stream, group) if with_consumer else 0
    return report.finish(latencies)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate synthetic events into the Redis events stream and measure.")
    ap.add_argument("--count", type=int, default=10_000)
    ap.add_argument("--rate", type=float, default=0, help="events per second, 0 = as fast as possible")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--attack-ratio", type=float, default=0.25)
    ap.add_argument("--stream", default="events")
    ap.add_argument("--group", default="detector")
    ap.add_argument("--consumers", type=int, default=1)
    ap.add_argument("--maxlen", type=int, default=None, help="cap the stream length (approximate)")
    ap.add_argument("--redis-url", default=None)
    ap.add_argument("--fake", action="store_true", help="use an in-memory Redis (no server needed)")
    ap.add_argument("--no-consumer", action="store_true", help="only generate (another service reads the stream)")
    ap.add_argument("--report-dir", default="loadgen/results")
    args = ap.parse_args(argv)
    report = run(args.count, args.rate, args.seed, args.attack_ratio, args.stream, args.group, args.consumers,
                 make_client(args.redis_url, args.fake), args.maxlen, not args.no_consumer)
    print(report.to_markdown())
    print("saved:", report.save(args.report_dir))
    return report


if __name__ == "__main__":
    main()
