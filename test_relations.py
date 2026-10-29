"""تيستات W2: ربط الأصول بالحوادث وغيرها. بتشتغل على database وهمية (mongomock)."""
import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.seed_data import SEED_ASSETS
from fixtures.loader import load_incidents

client = TestClient(app)


@pytest.fixture(autouse=True)
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    db = database.get_db()
    db["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    db["incidents"].insert_many(
        [{k: v for k, v in i.items() if k != "expected"} for i in load_incidents()])
    yield db
    database._client = old


def test_summary_of_asset_with_incidents():
    r = client.get("/assets/AST-001/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["asset"]["name"] == "skyline-web"
    assert {i["incident_id"] for i in body["incidents"]} == {"INC-002", "INC-004", "INC-005", "INC-008"}
    assert body["findings"] == [] and body["risks"] == [] and body["controls"] == []
    assert body["counts"] == {"incidents": 4, "findings": 0, "risks": 0, "controls": 0}


def test_every_incident_is_reachable_from_its_assets():
    for inc in load_incidents():
        for asset_id in inc["affected_assets"]:
            ids = {i["incident_id"] for i in client.get(f"/assets/{asset_id}/incidents").json()}
            assert inc["incident_id"] in ids


def test_expected_answers_are_not_exposed():
    for i in client.get("/assets/AST-001/incidents").json():
        assert "expected" not in i and "_id" not in i


def test_asset_without_relations_returns_empty_lists():
    body = client.get("/assets/AST-012/summary").json()
    assert body["counts"] == {"incidents": 0, "findings": 0, "risks": 0, "controls": 0}


def test_unknown_asset_returns_404():
    for path in ("summary", "incidents", "findings", "risks", "controls"):
        assert client.get(f"/assets/AST-999/{path}").status_code == 404


def test_findings_risks_controls_show_up_when_linked(fake_db):
    fake_db["findings"].insert_one({"finding_id": "F-1", "asset_ids": ["AST-001"]})
    fake_db["risks"].insert_one({"risk_id": "R-1", "asset_ids": ["AST-001", "AST-004"]})
    fake_db["controls"].insert_one({"control_id": "C-1", "asset_ids": ["AST-004"]})
    body = client.get("/assets/AST-001/summary").json()
    assert [f["finding_id"] for f in body["findings"]] == ["F-1"]
    assert [r["risk_id"] for r in body["risks"]] == ["R-1"]
    assert body["controls"] == []
    assert client.get("/assets/AST-004/summary").json()["counts"]["risks"] == 1