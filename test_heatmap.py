"""W7 tests: the heatmap data. They run on a fake in-memory database (mongomock)."""
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
    yield db
    database._client = old


def make(**over):
    body = dict(title="SQLi", asset_ids=["AST-001"], owner="Web Team", likelihood=4, impact=5)
    body.update(over)
    return body


def cell(heatmap, likelihood, impact):
    return next(c for c in heatmap["cells"]
                if c["likelihood"] == likelihood and c["impact"] == impact)


def test_heatmap_route_exists_and_has_25_cells():
    r = client.get("/risks/heatmap")  # must not be caught by /risks/{risk_id}
    assert r.status_code == 200
    body = r.json()
    assert len(body["cells"]) == 25 and body["total"] == 0
    assert body["bands"] == {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}


def test_risk_lands_in_the_right_cell():
    client.post("/risks", json=make())
    body = client.get("/risks/heatmap").json()
    c = cell(body, 4, 5)
    assert (c["count"], c["risk_ids"], c["band"], c["score"]) == (1, ["RSK-001"], "Critical", 20)
    assert body["total"] == 1 and body["bands"]["Critical"] == 1


def test_heatmap_moves_when_a_risk_changes():
    client.post("/risks", json=make())
    client.put("/risks/RSK-001", json={"likelihood": 2})
    body = client.get("/risks/heatmap").json()
    assert cell(body, 4, 5)["count"] == 0
    assert cell(body, 2, 5)["risk_ids"] == ["RSK-001"]
    assert body["bands"]["High"] == 1 and body["bands"]["Critical"] == 0


def test_residual_basis_uses_the_residual_values():
    client.post("/risks", json=make(residual_likelihood=2, residual_impact=5))
    assert cell(client.get("/risks/heatmap").json(), 4, 5)["count"] == 1
    residual = client.get("/risks/heatmap", params={"basis": "residual"}).json()
    assert cell(residual, 2, 5)["count"] == 1 and cell(residual, 4, 5)["count"] == 0


def test_closed_risks_are_hidden_unless_asked_for():
    client.post("/risks", json=make())
    client.put("/risks/RSK-001", json={"status": "closed"})
    assert client.get("/risks/heatmap").json()["total"] == 0
    assert client.get("/risks/heatmap", params={"include_closed": True}).json()["total"] == 1


def test_asset_filter():
    client.post("/risks", json=make(asset_ids=["AST-001"]))
    client.post("/risks", json=make(title="Auth", asset_ids=["AST-003"], likelihood=2, impact=2))
    assert client.get("/risks/heatmap").json()["total"] == 2
    only = client.get("/risks/heatmap", params={"asset_id": "AST-003"}).json()
    assert only["total"] == 1 and cell(only, 2, 2)["risk_ids"] == ["RSK-002"]


def test_live_recalculation_moves_the_risk_on_the_map(fake_db):
    """W4 + W7: real incidents change the risk, and the heatmap follows."""
    client.post("/risks", json=make(likelihood=3, impact=2))
    assert cell(client.get("/risks/heatmap").json(), 3, 2)["count"] == 1
    fake_db["incidents"].insert_many(
        [{k: v for k, v in i.items() if k != "expected"} for i in load_incidents()])
    assert client.post("/risks/recalculate", params={"days": 3650}).status_code == 200
    after = client.get("/risks/heatmap").json()
    assert cell(after, 3, 2)["count"] == 0
    assert cell(after, 4, 5)["risk_ids"] == ["RSK-001"]
