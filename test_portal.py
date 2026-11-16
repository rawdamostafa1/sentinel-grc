"""W8 tests: Client Portal summary. Run: python -m pytest test_portal.py -v"""
from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.portal_scoring import (ACTION_TEXT, automatic_actions, compliance_overview, incident_summary,
                                posture, posture_label, top_risks)
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


def risk(i, residual, status="open", **over):
    doc = dict(risk_id=f"RSK-{i:03d}", title=f"Risk {i}", status=status, residual_score=residual,
               inherent_score=residual, residual_band="High", asset_ids=["AST-001"], due_date="2026-12-01")
    doc.update(over)
    return doc


def incident(i, severity="high", **over):
    doc = dict(incident_id=f"INC-{i}", severity=severity, status="open", first_seen=now(),
               affected_assets=["AST-001"])
    doc.update(over)
    return doc


def action(tool="block_ip", result="success", **over):
    doc = dict(tool=tool, result=result, executed_at=now(), args={"ip": "203.0.113.7"})
    doc.update(over)
    return doc


# ---------- pure formulas ----------
def test_posture_score_and_labels():
    assert posture([risk(1, 25), risk(2, 25)])["score"] == 0
    assert posture([risk(1, 5), risk(2, 5)])["score"] == 80
    assert posture([risk(1, 10), risk(2, 20)])["score"] == 40          # average 15 -> 40
    assert [posture_label(s) for s in (100, 75, 74, 50, 49, 25, 24, 0)] == [
        "Good", "Good", "Fair", "Fair", "Needs attention", "Needs attention", "At risk", "At risk"]


def test_posture_counts_only_active_risks_and_is_none_for_an_empty_register():
    assert posture([]) is None
    assert posture([risk(1, 25, status="closed")]) is None
    assert posture([risk(1, 5), risk(2, 25, status="closed")])["active_risks"] == 1
    assert posture([risk(1, 10, status="accepted")])["score"] == 60


def test_top_risks_sorted_limited_and_show_asset_names_not_ids():
    risks = [risk(i, i) for i in range(1, 9)] + [risk(9, 25, status="closed")]
    top = top_risks(risks, {"AST-001": "skyline-web"})
    assert [r["risk_id"] for r in top] == ["RSK-008", "RSK-007", "RSK-006", "RSK-005", "RSK-004"]
    assert top[0]["assets"] == ["skyline-web"]


def test_incident_summary_ignores_noise():
    cutoff = now() - timedelta(days=30)
    items = [incident(1, "critical"), incident(2, "high", status="resolved"),
             incident(3, "low", status="false_positive"), incident(4, "high", labels=["authorized_test"]),
             incident(5, "high", first_seen=now() - timedelta(days=90)), incident(1, "critical")]
    summary = incident_summary(items, cutoff, 30)
    assert summary["total"] == 2 and summary["open"] == 1
    assert summary["by_severity"] == {"Critical": 1, "High": 1, "Medium": 0, "Low": 0}
    assert summary["handled_autonomously_percent"] is None            # no incident has the field yet


def test_autonomy_percent():
    items = [incident(1, handled_autonomously=True), incident(2, handled_autonomously=False),
             incident(3, handled_autonomously=True), incident(4)]
    assert incident_summary(items, now() - timedelta(days=30), 30)["handled_autonomously_percent"] == 66.7


def test_compliance_overview_reads_amiras_report_shape():
    snap = {"date": "2026-10-24", "frameworks": {"NIST": {"percent": 40.0}, "CIS": {"percent": 20.0},
                                                  "ISO": {"percent": None}}}
    out = compliance_overview(snap)
    assert out["percent"] == 30.0 and out["as_of"] == "2026-10-24" and out["frameworks"]["ISO"] is None
    assert compliance_overview(None) == {"percent": None, "frameworks": {}, "as_of": None}


def test_only_real_successful_actions_are_shown_without_addresses():
    items = [action("block_ip"), action("lock_account"), action("block_ip", result="rejected"),
             action("block_ip", result="failed"), action("block_ip", dry_run=True), action("notify"),
             action("something_new"), action("add_waf_rule", result={"success": True}), {"tool": "block_ip"}]
    shown = automatic_actions(items)
    assert [s["description"] for s in shown].count(ACTION_TEXT["block_ip"]) == 1
    assert len(shown) == 4
    assert "203.0.113.7" not in str(shown)


# ---------- the API ----------
def test_empty_database_returns_notes_instead_of_inventing_data():
    body = client.get("/portal/summary").json()
    assert body["posture"] is None and body["top_risks"] == [] and body["automatic_actions"] == []
    assert body["compliance"]["percent"] is None and body["reports"] == []
    assert body["incidents"]["total"] == 0
    assert len(body["notes"]) == 4


def test_full_summary(fake_db):
    fake_db["risks"].insert_many([risk(1, 20, residual_band="Critical"), risk(2, 5, residual_band="Medium")])
    fake_db["incidents"].insert_many([incident(1, "critical", handled_autonomously=True), incident(2)])
    fake_db["actions"].insert_many([action("block_ip"), action("block_ip", result="failed")])
    fake_db["compliance_snapshots"].insert_many([
        {"date": "2026-10-01", "frameworks": {"NIST": {"percent": 10.0}}},
        {"date": "2026-10-24", "frameworks": {"NIST": {"percent": 40.0}}}])
    fake_db["reports"].insert_one({"title": "Weekly executive report", "created_at": "2026-10-20", "url": "/r/1.pdf"})
    body = client.get("/portal/summary").json()
    assert body["posture"]["score"] == 50 and body["posture"]["label"] == "Fair"
    assert body["top_risks"][0]["risk_id"] == "RSK-001" and body["top_risks"][0]["assets"] == ["skyline-web"]
    assert body["incidents"]["total"] == 2 and body["incidents"]["handled_autonomously_percent"] == 100.0
    assert len(body["automatic_actions"]) == 1
    assert body["compliance"]["percent"] == 40.0                        # the newest snapshot wins
    assert body["reports"][0]["title"] == "Weekly executive report"
    assert body["notes"] == []


def test_days_parameter_changes_the_window(fake_db):
    fake_db["incidents"].insert_one(incident(1, first_seen=now() - timedelta(days=60)))
    assert client.get("/portal/summary").json()["incidents"]["total"] == 0
    assert client.get("/portal/summary", params={"days": 90}).json()["incidents"]["total"] == 1
    assert client.get("/portal/summary", params={"days": 0}).status_code == 422


def test_expired_acceptance_is_counted_again(fake_db):
    past = now() - timedelta(days=1)
    fake_db["risks"].insert_one(risk(1, 20, status="accepted", acceptance={"expires_at": past}))
    body = client.get("/portal/summary").json()
    assert body["top_risks"][0]["status"] == "open"


def test_no_internal_details_leak(fake_db):
    fake_db["incidents"].insert_one(incident(1, src_ip="203.0.113.7"))
    fake_db["actions"].insert_one(action())
    assert "203.0.113.7" not in str(client.get("/portal/summary").json())
