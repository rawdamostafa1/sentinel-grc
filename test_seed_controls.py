"""Tests for seed_controls.py: controls (Amira, Z1) linked to assets (W2).
The first test would have caught a renumbered asset list silently linking controls to the wrong assets."""
import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
import seed_controls
from app.main import app
from app.seed_data import SEED_ASSETS

client = TestClient(app)
ASSET_IDS = {a["asset_id"] for a in SEED_ASSETS}


@pytest.fixture(autouse=True)
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    database.get_db()["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    yield
    database._client = old


def test_every_asset_in_the_feature_table_exists():
    used = {a for ids in seed_controls.FEATURE_ASSETS.values() for a in ids}
    assert used <= ASSET_IDS, sorted(used - ASSET_IDS)


def test_features_point_to_the_asset_that_really_runs_them():
    by_id = {a["asset_id"]: a["name"] for a in SEED_ASSETS}
    expected = {"sniffer": "Sniffer", "log-shipper": "Log Shipper", "detector": "Detector",
                "correlation-engine": "Correlator", "enrichment-service": "Enrichment",
                "pentest-module": "Pentest Runner", "policy-guard": "Policy Guard & Playbooks",
                "audit-log": "Audit Log", "notification-engine": "Telegram Bot API"}
    for feature, name in expected.items():
        assert name in [by_id[a] for a in seed_controls.FEATURE_ASSETS[feature]], feature


def test_the_control_library_loads_and_every_link_is_valid():
    docs = seed_controls.build_docs(seed_controls.load_control_files())
    assert len(docs) == 362
    assert len({d["control_id"] for d in docs}) == 362
    for d in docs:
        assert set(d["asset_ids"]) <= ASSET_IDS


def test_seeding_is_repeatable_and_the_asset_page_shows_controls():
    assert seed_controls.run() == 362
    seed_controls.run()
    assert database.get_controls().count_documents({}) == 362
    guard = client.get("/assets/AST-023/controls").json()
    assert guard and all("AST-023" in c["asset_ids"] for c in guard)
    assert client.get("/assets/AST-023/summary").json()["counts"]["controls"] == len(guard)
    assert client.get("/assets/AST-029/controls").json()          # Telegram: notification controls


def test_assets_with_no_platform_feature_have_no_controls():
    seed_controls.run()
    assert client.get("/assets/AST-021/controls").json() == []    # Booking flow: a website part, not a platform feature
