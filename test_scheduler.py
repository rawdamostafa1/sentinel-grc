"""W4 tests: the automatic recalculation job. Run: python -m pytest test_scheduler.py -v"""
import asyncio
from datetime import datetime, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.scheduler import RecalcJob
from app.seed_data import SEED_ASSETS

client = TestClient(app)


@pytest.fixture(autouse=True)
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    db = database.get_db()
    db["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    yield db
    database._client = old


async def wait_until(condition, timeout=5.0):
    """Poll until condition() is true, or give up after `timeout` seconds."""
    end = asyncio.get_running_loop().time() + timeout
    while not condition():
        if asyncio.get_running_loop().time() > end:
            return False
        await asyncio.sleep(0.02)
    return True


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def make_risk(likelihood=2):
    body = dict(title="SQLi", asset_ids=["AST-001"], owner="Web Team", likelihood=likelihood, impact=2)
    assert client.post("/risks", json=body).status_code == 201


def attacks(db, n=2):
    db["incidents"].insert_many([dict(incident_id=f"INC-{i}", affected_assets=["AST-001"], severity="critical",
                                      first_seen=now(), status="open") for i in range(n)])


def test_run_once_recalculates_and_records_the_result(fake_db):
    make_risk(likelihood=2)
    attacks(fake_db)
    job = RecalcJob()
    result = job.run_once()
    assert result["checked"] == 1 and job.runs == 1 and job.last_error is None and job.last_run
    assert client.get("/risks/RSK-001").json()["likelihood"] == 3            # 2 critical incidents -> +1


def test_a_failed_run_is_recorded_and_does_not_raise(monkeypatch):
    import app.scheduler as scheduler

    def boom(_days):
        raise RuntimeError("database is down")
    monkeypatch.setattr(scheduler, "recalculate_all", boom)
    job = RecalcJob()
    assert job.run_once() is None
    assert job.failures == 1 and "database is down" in job.last_error and job.runs == 0


def test_the_risk_moves_by_itself_while_the_job_runs(fake_db):
    """The plan's 'done when': a new attack changes the risk score without anybody pressing a button."""
    make_risk(likelihood=2)

    async def scenario():
        job = RecalcJob()
        job.start(interval=0.05, days=30)
        await wait_until(lambda: job.runs >= 2)
        before = client.get("/risks/RSK-001").json()["likelihood"]
        attacks(fake_db)                                    # a new attack arrives
        await wait_until(lambda: client.get("/risks/RSK-001").json()["likelihood"] == 3)
        after = client.get("/risks/RSK-001").json()["likelihood"]
        runs = job.runs
        await job.stop()
        return before, after, runs, job.running
    before, after, runs, still_running = asyncio.run(scenario())
    assert (before, after) == (2, 3) and runs >= 2 and still_running is False


def test_the_loop_survives_a_failure(monkeypatch):
    import app.scheduler as scheduler
    calls = {"n": 0}

    def flaky(_days):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first run fails")
        return {"checked": 0, "changed": 0, "skipped": 0, "window_days": 30}
    monkeypatch.setattr(scheduler, "recalculate_all", flaky)

    async def scenario():
        job = RecalcJob()
        job.start(interval=0.05)
        await wait_until(lambda: job.runs >= 2)
        await job.stop()
        return job
    job = asyncio.run(scenario())
    assert job.failures == 1 and job.runs >= 2


def test_interval_zero_keeps_the_job_off():
    async def scenario():
        job = RecalcJob()
        job.start(interval=0)
        return job.running
    assert asyncio.run(scenario()) is False


def test_status_endpoint_and_lifespan(monkeypatch):
    monkeypatch.setenv("RECALC_INTERVAL_SECONDS", "0")
    with TestClient(app) as running:                       # runs the startup/shutdown code
        body = running.get("/risks/recalculate/status").json()
    assert body["enabled"] is False and {"runs", "failures", "last_run", "last_error"} <= set(body)
    monkeypatch.setenv("RECALC_INTERVAL_SECONDS", "0.05")
    with TestClient(app) as running:
        import time
        end = time.monotonic() + 5
        body = running.get("/risks/recalculate/status").json()
        while body["runs"] < 2 and time.monotonic() < end:
            time.sleep(0.05)
            body = running.get("/risks/recalculate/status").json()
    assert body["enabled"] is True and body["runs"] >= 2 and body["last_result"]["checked"] == 0
    from app.scheduler import job
    assert job.running is False                            # stopped cleanly on shutdown


def test_the_status_route_is_not_mistaken_for_a_risk():
    assert client.get("/risks/recalculate/status").status_code == 200
