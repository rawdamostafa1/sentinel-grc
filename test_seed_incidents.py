"""The incident seeder must cope with incidents saved by the older script (no "source" field)."""
import mongomock
import pytest

import app.database as database
import seed_incidents
from fixtures.loader import load_incidents


@pytest.fixture(autouse=True)
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    yield database.get_db()
    database._client = old


def legacy_docs():
    # exactly what the old script stored: the fixture incident without "source" and without "expected"
    return [{k: v for k, v in i.items() if k != "expected"} for i in load_incidents()]


def test_old_copies_are_replaced_instead_of_crashing_on_the_unique_index(fake_db):
    fake_db["incidents"].insert_many(legacy_docs())
    assert seed_incidents.run() == 9
    docs = list(fake_db["incidents"].find({}))
    assert len(docs) == 9 and all(d["source"] == "fixture" for d in docs)


def test_a_real_incident_is_never_deleted(fake_db):
    real = {"incident_id": "INC-100", "src_ip": "203.0.113.5", "first_seen": "2026-11-01T10:00:00Z",
            "affected_assets": ["AST-001"], "status": "open"}
    fake_db["incidents"].insert_one(dict(real))
    seed_incidents.run()
    assert fake_db["incidents"].count_documents({"incident_id": "INC-100"}) == 1
    seed_incidents.remove()                                   # removes only the fixtures
    assert [d["incident_id"] for d in fake_db["incidents"].find({})] == ["INC-100"]


def test_running_twice_does_not_duplicate(fake_db):
    seed_incidents.run()
    seed_incidents.run()
    assert fake_db["incidents"].count_documents({}) == 9
