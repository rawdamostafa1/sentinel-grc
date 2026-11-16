"""W9 tests: the synthetic data and load generator. Everything runs on an in-memory Redis (fakeredis).
Run: python -m pytest test_loadgen.py -v"""
import json
from collections import Counter
from datetime import datetime, timezone

import fakeredis
import pytest

from fixtures.loader import list_scenarios, load_events
from loadgen.consume import consume, ensure_group, pending
from loadgen.events import ATTACKS, EVENT_FIELDS, EventFactory, LoadConfig
from loadgen.metrics import Report, percentile
from loadgen.sinks import JsonlSink, RedisSink, send
from loadgen.stress import main, run

START = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)


def factory(count=10_000, seed=7, **kw):
    return EventFactory(LoadConfig(count=count, seed=seed, start=START, **kw))


@pytest.fixture()
def redis_client():
    return fakeredis.FakeRedis(server=fakeredis.FakeServer(), decode_responses=True)


# ---------- the events ----------
def test_events_use_the_same_schema_as_the_fixtures():
    fixture_fields = {k for s in list_scenarios() for e in load_events(s) for k in e}
    assert set(EVENT_FIELDS) == fixture_fields
    assert all(set(e) == set(EVENT_FIELDS) for e in factory(500).events())


def test_exactly_the_requested_number_of_unique_events():
    events = list(factory(10_000).events())
    assert len(events) == 10_000 and len({e["event_id"] for e in events}) == 10_000


def test_same_seed_same_events_different_seed_different_events():
    first = [e["src_ip"] for e in factory(800, seed=1).events()]
    assert first == [e["src_ip"] for e in factory(800, seed=1).events()]
    assert first != [e["src_ip"] for e in factory(800, seed=2).events()]


def test_traffic_is_varied_in_addresses_ports_times_and_types():
    events = list(factory(10_000).events())
    assert len({e["src_ip"] for e in events}) > 500 and len({e["src_port"] for e in events}) > 5_000
    times = sorted(e["ts"] for e in events)
    assert len({t[:16] for t in times}) > 30                                  # spread over many minutes
    kinds = Counter(e["event_type"] for e in events)
    assert {"http_request", "login_failed", "login_ok", "flow"} <= set(kinds)
    assert {"GET", "POST"} <= {e["http_method"] for e in events if e["http_method"]}
    assert {200, 401, 404, 429, 500} <= {e["status"] for e in events if e["status"]}


def test_every_attack_type_and_the_false_positive_case_appear():
    f = factory(100)
    for kind in ATTACKS + ("heavy_user", "login", "browsing", "flow"):
        session = f.session(kind, START)
        assert session and all(e["event_id"] for e in session), kind
    heavy = f.session("heavy_user", START)
    assert {e["status"] for e in heavy if e["status"]} == {200}                # a busy customer is not an attack


def test_attack_ratio_controls_the_share_of_attack_traffic():
    def attack_share(ratio):
        events = list(factory(6_000, attack_ratio=ratio).events())
        bad = sum(1 for e in events if e["event_type"] == "login_failed" or (e["status"] in (404, 429, 500) and e["event_type"] == "http_request"))
        return bad / len(events)
    assert attack_share(0.0) < 0.06 < attack_share(0.6)


def test_only_reserved_or_lab_addresses_are_generated():
    for e in factory(3_000).events():
        ip = e["src_ip"]
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "100.")), ip
        assert e["dst_ip"] in {"172.18.0.5", "172.18.0.10"}


# ---------- sinks, pacing ----------
def test_redis_sink_writes_messages_in_the_documented_format(redis_client):
    sent, _ = send(factory(250), RedisSink(redis_client, "events"))
    assert sent == 250 and redis_client.xlen("events") == 250
    _id, fields = redis_client.xrange("events", count=1)[0]
    assert set(fields) == {"event_id", "sent_at_ms", "data"} and json.loads(fields["data"])["event_id"] == fields["event_id"]


def test_the_stream_can_be_capped(redis_client):
    send(factory(2_000), RedisSink(redis_client, "events", maxlen=100))
    assert 100 <= redis_client.xlen("events") < 2_000


def test_jsonl_sink(tmp_path):
    sink = JsonlSink(tmp_path / "events.jsonl")
    send(factory(300), sink)
    sink.close()
    assert len((tmp_path / "events.jsonl").read_text().splitlines()) == 300


def test_rate_limit_slows_the_sender_down():
    """200 events at 400 per second must take about half a second, however fast or slow the computer is."""
    sink = lambda: RedisSink(fakeredis.FakeRedis(server=fakeredis.FakeServer()), "events")
    _, fast = send(factory(200), sink(), rate=0)
    _, slow = send(factory(200), sink(), rate=400)
    assert 0.45 <= slow < 2.0               # paced: 200 / 400 = 0.5 seconds
    assert fast < slow                      # unlimited is quicker (a slow computer still does 200 events in far under 0.5 s)


# ---------- end to end: the plan's "ten thousand events processed end to end; metrics collected" ----------
def test_ten_thousand_events_go_through_the_stream_without_loss():
    report = run(count=10_000, seed=3, consumers=2, idle_seconds=1.0)
    assert report.sent == 10_000 and report.processed == 10_000
    assert report.lost == 0 and report.duplicates == 0 and report.dead_letter == 0 and report.pending_at_end == 0
    assert report.stream_length == 10_000 and report.send_rate > 0 and report.process_rate > 0
    assert all(report.latency_ms[k] is not None and report.latency_ms[k] >= 0 for k in ("p50", "p95", "p99", "max"))
    assert report.latency_ms["p50"] <= report.latency_ms["p95"] <= report.latency_ms["p99"] <= report.latency_ms["max"]


def test_malformed_messages_go_to_the_dead_letter_stream(redis_client):
    send(factory(300), RedisSink(redis_client, "events"))
    redis_client.xadd("events", {"event_id": "bad-1", "sent_at_ms": "1", "data": "{not json"})
    redis_client.xadd("events", {"event_id": "bad-2", "sent_at_ms": "1", "data": "[]"})
    report = consume(redis_client, "events", "detector", "w1", idle_seconds=0.5)
    assert report.processed == 300 and report.dead_letter == 2 and redis_client.xlen("events:dead") == 2


def test_a_worker_that_dies_before_acknowledging_leaves_events_pending(redis_client):
    send(factory(100), RedisSink(redis_client, "events"))
    ensure_group(redis_client, "events", "detector")
    redis_client.xreadgroup("detector", "crashed-worker", {"events": ">"}, count=40)    # read, never acknowledged
    assert pending(redis_client, "events", "detector") == 40
    report = consume(redis_client, "events", "detector", "w2", idle_seconds=0.5)         # only new messages
    assert report.processed == 60 and pending(redis_client, "events", "detector") == 40  # the 40 wait to be claimed


def test_without_a_consumer_the_run_only_generates():
    report = run(count=500, with_consumer=False)
    assert report.sent == 500 and report.processed == 0 and report.pending_at_end == 0


# ---------- the numbers and the report ----------
def test_percentile_uses_the_nearest_rank():
    values = list(range(1, 101))
    assert (percentile(values, 50), percentile(values, 95), percentile(values, 99), percentile(values, 100)) == (50, 95, 99, 100)
    assert percentile([], 50) is None and percentile([7], 99) == 7


def test_report_is_saved_as_json_and_markdown(tmp_path):
    report = run(count=300, idle_seconds=0.5)
    path = report.save(tmp_path)
    assert path.suffix == ".md" and "detection accuracy" in path.read_text()
    assert json.loads(next(tmp_path.glob("*.json")).read_text())["processed"] == 300


def test_command_line_entry_point(tmp_path, capsys):
    report = main(["--fake", "--count", "400", "--report-dir", str(tmp_path)])
    assert report.processed == 400 and "Stress test report" in capsys.readouterr().out
