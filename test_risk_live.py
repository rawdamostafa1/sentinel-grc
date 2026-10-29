"""W4 tests: live risk calculation. Run: python -m pytest test_risk_live.py -v"""
from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.risk_live_scoring import (counted_incidents, evidence_points, live_impact,
                                   live_likelihood, open_findings)
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


def make(**over):
    body = dict(title="SQLi", asset_ids=["AST-001"], owner="Web Team", likelihood=2, impact=2)
    body.update(over)
    return body


def incident(i, severity="critical", asset="AST-001", **over):
    doc = dict(incident_id=f"INC-{i}", affected_assets=[asset], severity=severity,
               first_seen=now(), status="open")
    doc.update(over)
    return doc


def finding(i, severity="critical", asset="AST-001", **over):
    doc = dict(finding_id=f"F-{i}", asset_ids=[asset], severity=severity, status="open")
    doc.update(over)
    return doc


def recalc(**params):
    r = client.post("/risks/recalculate", params=params)
    assert r.status_code == 200
    return r.json()


def get(risk_id="RSK-001"):
    return client.get(f"/risks/{risk_id}").json()


# ---------- pure formulas ----------
def test_impact_comes_from_criticality_and_data_class():
    web = {"criticality": 5, "data_classification": "confidential"}
    lb = {"criticality": 5, "data_classification": "internal"}
    duffel = {"criticality": 3, "data_classification": "confidential"}
    assert live_impact([web]) == 5
    assert live_impact([lb]) == 4          # 0.7*5 + 0.3*3 = 4.4
    assert live_impact([duffel]) == 4      # 0.7*3 + 0.3*5 = 3.6
    assert live_impact([lb, duffel]) == 5  # the worst criticality and class win
    assert live_impact([]) is None


def test_likelihood_is_capped_between_1_and_5():
    assert live_likelihood(2, 0) == 2
    assert live_likelihood(2, 1.0) == 3
    assert live_likelihood(4, 4.0) == 5
    assert live_likelihood(1, 0.4) == 1


def test_points_cap_and_bonus():
    many = [incident(i) for i in range(10)]
    pts = evidence_points(many, [])
    assert pts["incident_points"] == 2.0 and pts["link_bonus"] == 0
    pts = evidence_points([incident(1)], [finding(1)])
    assert pts["link_bonus"] == 0.5 and pts["total_points"] == 1.5


def test_filters_ignore_false_positives_authorized_tests_and_old_incidents():
    cutoff = now() - timedelta(days=30)
    items = [incident(1), incident(1),                       # duplicate id counts once
             incident(2, status="false_positive"),
             incident(3, labels=["authorized_test"]),
             incident(4, authorized_test=True),
             incident(5, first_seen=now() - timedelta(days=90)),
             incident(6, first_seen=(now() - timedelta(days=1)).isoformat())]
    assert [i["incident_id"] for i in counted_incidents(items, cutoff)] == ["INC-1", "INC-6"]
    fs = [finding(1), finding(2, status="fixed"), finding(3, status="Resolved"), finding(4)]
    assert [f["finding_id"] for f in open_findings(fs)] == ["F-1", "F-4"]


# ---------- the API ----------
def test_without_evidence_likelihood_stays_and_impact_is_computed():
    client.post("/risks", json=make(likelihood=3, impact=1))
    summary = recalc()
    assert summary["checked"] == 1 and summary["changed"] == 1
    risk = get()
    assert risk["likelihood"] == 3                    # baseline kept
    assert risk["impact"] == 5                        # skyline-web: criticality 5, confidential
    assert risk["inherent_score"] == 15 and risk["inherent_band"] == "High"
    assert risk["last_recalculated"] is not None


def test_incidents_raise_the_risk_and_it_falls_back_when_they_go_away(fake_db):
    client.post("/risks", json=make(likelihood=2))
    fake_db["incidents"].insert_many([incident(1), incident(2)])
    recalc()
    risk = get()
    assert risk["likelihood"] == 3                    # 2 critical -> 1.0 point
    assert risk["live_factors"]["incident_count"] == 2
    assert risk["base_likelihood"] == 2
    fake_db["incidents"].delete_many({})
    recalc()
    assert get()["likelihood"] == 2


def test_findings_plus_attacks_get_the_bonus(fake_db):
    client.post("/risks", json=make(likelihood=2))
    fake_db["incidents"].insert_many([incident(1), incident(2)])
    fake_db["findings"].insert_many([finding(1), finding(2)])
    recalc()
    risk = get()
    assert risk["live_factors"]["total_points"] == 2.5
    assert risk["likelihood"] == 5                    # 2 + round(2.5) = 5


def test_fixed_finding_lowers_the_risk(fake_db):
    client.post("/risks", json=make(likelihood=2))
    fake_db["findings"].insert_many([finding(1), finding(2)])
    recalc()
    assert get()["likelihood"] == 3
    fake_db["findings"].update_many({}, {"$set": {"status": "fixed"}})
    recalc()
    assert get()["likelihood"] == 2


def test_old_incidents_are_outside_the_window_unless_days_is_larger(fake_db):
    client.post("/risks", json=make(likelihood=2))
    fake_db["incidents"].insert_many(
        [incident(i, first_seen=now() - timedelta(days=90)) for i in (1, 2)])
    recalc()
    assert get()["likelihood"] == 2
    recalc(days=120)
    assert get()["likelihood"] == 3


def test_pentest_traffic_and_false_positives_do_not_raise_risk(fake_db):
    client.post("/risks", json=make(likelihood=2))
    fake_db["incidents"].insert_many([incident(1, labels=["authorized_test"]),
                                      incident(2, status="false_positive")])
    recalc()
    assert get()["likelihood"] == 2


def test_accepted_closed_and_manual_risks_are_skipped(fake_db):
    client.post("/risks", json=make(title="a"))
    client.post("/risks", json=make(title="b"))
    client.post("/risks", json=make(title="c", auto_update=False, impact=1))
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    client.post("/risks/RSK-001/accept", json=dict(accepted_by="CISO", reason="x", expires_at=future))
    client.put("/risks/RSK-002", json={"status": "closed"})
    summary = recalc()
    assert summary["skipped"] == 3 and summary["checked"] == 0
    assert get("RSK-003")["impact"] == 1


def test_analyst_change_becomes_the_new_baseline(fake_db):
    client.post("/risks", json=make(likelihood=2))
    fake_db["incidents"].insert_many([incident(1), incident(2)])
    recalc()
    assert get()["likelihood"] == 3
    client.put("/risks/RSK-001", json={"likelihood": 4})
    assert get()["base_likelihood"] == 4
    recalc()
    assert get()["likelihood"] == 5


def test_history_keeps_a_snapshot_per_run(fake_db):
    client.post("/risks", json=make(likelihood=2))
    recalc()
    fake_db["incidents"].insert_many([incident(1), incident(2)])
    recalc()
    history = client.get("/risks/RSK-001/history").json()
    assert [h["likelihood"] for h in history] == [2, 3]
    assert history[1]["incident_count"] == 2 and "inherent_score" in history[1]
    assert client.get("/risks/RSK-999/history").status_code == 404


def test_seeded_style_risk_without_new_fields_still_works(fake_db):
    # a risk saved before W4 (no base_likelihood, no auto_update) must be recalculated safely
    client.post("/risks", json=make(likelihood=3))
    fake_db["risks"].update_one({"risk_id": "RSK-001"},
                                {"$unset": {"base_likelihood": "", "auto_update": ""}})
    assert recalc()["checked"] == 1
    assert get()["likelihood"] == 3