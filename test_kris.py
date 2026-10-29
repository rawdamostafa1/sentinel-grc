"""W5 tests: Key Risk Indicators. Run: python -m pytest test_kris.py -v"""
from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.kri_calc import (autonomy_rate, count_past, finding_ageing, mean_time_to_remediate,
                          open_critical_count)
from app.main import app
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


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def ago(days):
    return now() - timedelta(days=days)


def finding(i, severity="high", status="open", opened=None, closed=None):
    doc = dict(finding_id=f"F-{i}", asset_ids=["AST-001"], severity=severity, status=status)
    if opened is not None:
        doc["opened_at"] = opened
    if closed is not None:
        doc["closed_at"] = closed
    return doc


def sample_findings():
    return [finding(1, "critical", "open", ago(40)),
            finding(2, "high", "open", ago(10)),
            finding(3, "critical", "fixed", ago(20), ago(10)),   # fixed in 10 days
            finding(4, "high", "resolved", ago(30), ago(10))]    # fixed in 20 days


def all_kris():
    body = client.get("/kris").json()
    return {k["key"]: k for k in body["kris"]}


def make_risk(**over):
    body = dict(title="r", asset_ids=["AST-001"], owner="Web Team", likelihood=2, impact=2)
    body.update(over)
    assert client.post("/risks", json=body).status_code == 201


# ---------- pure formulas ----------
def test_open_critical_ignores_fixed_ones():
    assert open_critical_count(sample_findings()) == 1


def test_mean_time_to_remediate_uses_only_fixed_findings():
    result = mean_time_to_remediate(sample_findings())
    assert result == {"mean_days": 15.0, "sample": 2}
    assert mean_time_to_remediate([finding(1, opened=ago(5))]) is None


def test_ageing_average_oldest_and_buckets():
    result = finding_ageing(sample_findings(), now())
    assert result["average_days"] == 25.0 and result["oldest_days"] == 40.0
    assert result["buckets"] == {"0-7": 0, "8-30": 1, "31-90": 1, ">90": 0}
    assert finding_ageing([finding(1)], now()) is None                 # no date, cannot age it
    assert finding_ageing([finding(1, status="fixed")], now())["average_days"] == 0.0


def test_autonomy_rate_skips_pentest_and_incidents_without_the_field():
    incidents = [dict(incident_id="1", handled_autonomously=True),
                 dict(incident_id="2", handled_autonomously=True),
                 dict(incident_id="3", handled_autonomously=False),
                 dict(incident_id="4", handled_autonomously=True, labels=["authorized_test"]),
                 dict(incident_id="5")]
    assert autonomy_rate(incidents) == {"percent": 66.7, "autonomous": 2, "total": 3}
    assert autonomy_rate([dict(incident_id="5")]) is None


def test_count_past():
    docs = [{"d": ago(1)}, {"d": now() + timedelta(days=1)}, {"d": "2020-01-01"}, {}]
    assert count_past(docs, "d", now()) == 2


# ---------- the API ----------
def test_empty_database_says_no_data_instead_of_inventing_numbers():
    k = all_kris()
    assert set(k) == {"open_critical_findings", "mean_time_to_remediate", "finding_ageing",
                      "autonomy_rate", "attack_coverage", "expired_exceptions",
                      "policy_review_overdue", "critical_risks", "overdue_risks"}
    for key in ("open_critical_findings", "mean_time_to_remediate", "finding_ageing",
                "autonomy_rate", "attack_coverage", "policy_review_overdue"):
        assert k[key]["status"] == "no_data" and k[key]["value"] is None and k[key]["note"]
    for key in ("expired_exceptions", "critical_risks", "overdue_risks"):
        assert k[key]["status"] == "ok" and k[key]["value"] == 0


def test_finding_kris(fake_db):
    fake_db["findings"].insert_many(sample_findings())
    k = all_kris()
    assert k["open_critical_findings"]["value"] == 1
    assert k["mean_time_to_remediate"]["value"] == 15.0
    assert k["finding_ageing"]["value"] == 25.0
    assert k["finding_ageing"]["details"]["buckets"]["31-90"] == 1


def test_autonomy_kri(fake_db):
    fake_db["incidents"].insert_many([
        dict(incident_id="1", handled_autonomously=True), dict(incident_id="2", handled_autonomously=False)])
    k = all_kris()["autonomy_rate"]
    assert k["value"] == 50.0 and k["details"] == {"autonomous": 1, "total": 2}


def test_expired_exceptions_counts_risk_acceptances_and_policy_exceptions(fake_db):
    make_risk()
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    client.post("/risks/RSK-001/accept", json=dict(accepted_by="CISO", reason="x", expires_at=future))
    assert all_kris()["expired_exceptions"]["value"] == 0
    fake_db["risks"].update_one({"risk_id": "RSK-001"}, {"$set": {"acceptance.expires_at": ago(1)}})
    fake_db["policy_exceptions"].insert_many([{"expires_at": ago(2)}, {"expires_at": now() + timedelta(days=5)}])
    k = all_kris()["expired_exceptions"]
    assert k["value"] == 2 and k["details"] == {"risk_acceptances": 1, "policy_exceptions": 1}


def test_policy_review_overdue(fake_db):
    fake_db["policies"].insert_many([{"policy_id": "P1", "review_date": "2020-01-01"},
                                     {"policy_id": "P2", "review_date": "2099-01-01"}])
    k = all_kris()["policy_review_overdue"]
    assert k["status"] == "ok" and k["value"] == 1


def test_risk_register_kris():
    make_risk(likelihood=5, impact=5, due_date="2020-01-01")              # critical and overdue
    make_risk(likelihood=1, impact=1, due_date="2099-01-01")              # low, not due
    make_risk(likelihood=5, impact=5, due_date="2020-01-01")
    client.put("/risks/RSK-003", json={"status": "closed"})               # closed risks do not count
    k = all_kris()
    assert k["critical_risks"]["value"] == 1
    assert k["overdue_risks"]["value"] == 1