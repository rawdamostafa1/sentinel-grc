"""تيستات W3: سجل المخاطر (scoring، فلاتر، قبول بانتهاء). بتشتغل على database وهمية."""
from datetime import datetime, timedelta, timezone

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.risk_scoring import band_for
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


def make(**over):
    body = dict(title="SQLi", asset_ids=["AST-001"], owner="Web Team", likelihood=4, impact=5)
    body.update(over)
    return body


def past_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)


def future(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def test_bands_follow_the_spec():
    expected = {1: "Low", 4: "Low", 5: "Medium", 9: "Medium", 10: "High",
                16: "High", 17: "Critical", 25: "Critical"}
    for score, band in expected.items():
        assert band_for(score) == band


def test_create_scores_the_risk_and_residual_defaults_to_inherent():
    r = client.post("/risks", json=make())
    assert r.status_code == 201
    risk = r.json()
    assert risk["risk_id"] == "RSK-001"
    assert (risk["inherent_score"], risk["inherent_band"]) == (20, "Critical")
    assert (risk["residual_score"], risk["residual_band"]) == (20, "Critical")
    assert risk["status"] == "open" and risk["treatment"] == "mitigate"


def test_residual_score_is_separate():
    risk = client.post("/risks", json=make(residual_likelihood=2, residual_impact=5)).json()
    assert risk["inherent_score"] == 20
    assert (risk["residual_score"], risk["residual_band"]) == (10, "High")


def test_validation_rejects_bad_input():
    assert client.post("/risks", json=make(likelihood=6)).status_code == 422
    assert client.post("/risks", json=make(impact=0)).status_code == 422
    assert client.post("/risks", json=make(asset_ids=[])).status_code == 422
    assert client.post("/risks", json=make(asset_ids=["AST-999"])).status_code == 422
    # القبول لازم يعدّي على /accept
    assert client.post("/risks", json=make(treatment="accept")).status_code == 422
    assert client.post("/risks", json=make(status="accepted")).status_code == 422


def test_ids_are_sequential_and_never_reused():
    assert client.post("/risks", json=make()).json()["risk_id"] == "RSK-001"
    assert client.post("/risks", json=make()).json()["risk_id"] == "RSK-002"
    assert client.delete("/risks/RSK-001").status_code == 204
    assert client.post("/risks", json=make()).json()["risk_id"] == "RSK-003"


def test_list_is_sorted_by_score_and_filters_work():
    client.post("/risks", json=make(title="low", likelihood=1, impact=2))
    client.post("/risks", json=make(title="top", likelihood=5, impact=5, asset_ids=["AST-003"]))
    client.post("/risks", json=make(title="mid", likelihood=2, impact=4))
    titles = [r["title"] for r in client.get("/risks").json()]
    assert titles == ["top", "mid", "low"]
    assert [r["title"] for r in client.get("/risks", params={"band": "Critical"}).json()] == ["top"]
    assert {r["title"] for r in client.get("/risks", params={"asset_id": "AST-001"}).json()} == {"low", "mid"}
    assert [r["title"] for r in client.get("/risks", params={"min_score": 8}).json()] == ["top", "mid"]


def test_update_recalculates_the_score():
    client.post("/risks", json=make())
    r = client.put("/risks/RSK-001", json={"likelihood": 1}).json()
    assert (r["inherent_score"], r["inherent_band"]) == (5, "Medium")
    assert r["title"] == "SQLi"  # باقي الحقول ماتغيّرتش
    assert client.put("/risks/RSK-001", json={"treatment": "accept"}).status_code == 422
    assert client.put("/risks/RSK-999", json={"likelihood": 2}).status_code == 404


def test_acceptance_needs_owner_reason_and_future_expiry():
    client.post("/risks", json=make())
    ok = client.post("/risks/RSK-001/accept",
                     json=dict(accepted_by="CISO", reason="Cost too high", expires_at=future()))
    assert ok.status_code == 200
    body = ok.json()
    assert body["status"] == "accepted" and body["treatment"] == "accept"
    assert body["acceptance"]["accepted_by"] == "CISO"
    past = client.post("/risks/RSK-001/accept",
                       json=dict(accepted_by="CISO", reason="x", expires_at=future(-1)))
    assert past.status_code == 422
    assert client.post("/risks/RSK-001/accept",
                       json=dict(accepted_by="", reason="x", expires_at=future())).status_code == 422
    assert client.post("/risks/RSK-999/accept",
                       json=dict(accepted_by="a", reason="b", expires_at=future())).status_code == 404


def test_expired_acceptance_reappears_automatically(fake_db):
    client.post("/risks", json=make())
    client.post("/risks/RSK-001/accept",
                json=dict(accepted_by="CISO", reason="temporary", expires_at=future()))
    # نخلّي تاريخ الانتهاء في الماضي مباشرة في الـ database
    fake_db["risks"].update_one({"risk_id": "RSK-001"},
        {"$set": {"acceptance.expires_at": past_naive()}})
    risk = client.get("/risks/RSK-001").json()
    assert risk["status"] == "open" and risk["acceptance_expired"] is True
    assert client.get("/risks", params={"status": "accepted"}).json() == []


def test_risks_appear_in_the_asset_summary_even_after_expiry(fake_db):
    client.post("/risks", json=make(asset_ids=["AST-001", "AST-004"]))
    for asset in ("AST-001", "AST-004"):
        body = client.get(f"/assets/{asset}/summary").json()
        assert body["counts"]["risks"] == 1
        assert body["risks"][0]["risk_id"] == "RSK-001"
    assert client.get("/assets/AST-002/summary").json()["counts"]["risks"] == 0
    # قبول منتهي: summary لازم يشوفه open
    client.post("/risks/RSK-001/accept", json=dict(accepted_by="a", reason="b", expires_at=future()))
    fake_db["risks"].update_one({"risk_id": "RSK-001"},
        {"$set": {"acceptance.expires_at": past_naive()}})
    assert client.get("/assets/AST-001/summary").json()["risks"][0]["status"] == "open"


def test_get_and_delete_unknown_risk_return_404():
    assert client.get("/risks/RSK-999").status_code == 404
    assert client.delete("/risks/RSK-999").status_code == 404