"""Tests for the findings fixtures (W10) and what they feed: W2 asset page, W4 live risk, W5 KRIs.
Runs on a fake database. Run: python -m pytest test_findings.py -v"""
import json
import re
from datetime import datetime
from pathlib import Path

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
import seed_findings
import seed_risks
from app.kri_calc import finding_ageing, mean_time_to_remediate, open_critical_count
from app.main import app
from app.risk_live_scoring import open_findings
from app.seed_data import SEED_ASSETS
from fixtures.loader import load_events, load_finding, load_findings, load_incidents

client = TestClient(app)
ASSET_IDS = {a["asset_id"] for a in SEED_ASSETS}
OWASP_IDS = {c["category_id"] for c in json.loads(
    (Path(__file__).parent / "controls_data" / "owasp_top10.json").read_text(encoding="utf-8"))}
REQUIRED = {"finding_id", "title", "endpoint", "cwe", "owasp", "cvss", "severity", "status", "evidence",
            "tool", "asset_ids", "opened_at"}
NOW = datetime(2026, 10, 22, 9, 0, 0)      # the day the fixtures were written


@pytest.fixture()
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    db = database.get_db()
    db["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    seed_findings.run()
    yield db
    database._client = old


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "")) if value else None


def rating(cvss):
    return "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"


# ---------- the fixture file itself ----------
def test_every_finding_follows_the_finding_record_contract():
    ids = set()
    for f in load_findings():
        assert REQUIRED <= set(f), f["finding_id"]
        assert re.fullmatch(r"FND-\d{3}", f["finding_id"]) and f["finding_id"] not in ids
        ids.add(f["finding_id"])
        assert re.fullmatch(r"CWE-\d+", f["cwe"]) and f["owasp"] in OWASP_IDS
        assert f["endpoint"] and f["evidence"] and f["title"]


def test_severity_matches_the_cvss_rating():
    for f in load_findings():
        assert f["severity"] == rating(f["cvss"]), f["finding_id"]


def test_findings_point_to_real_assets():
    for f in load_findings():
        assert f["asset_ids"] and set(f["asset_ids"]) <= ASSET_IDS, f["finding_id"]


def test_dates_and_statuses_make_sense():
    for f in load_findings():
        assert f["status"] in {"open", "fixed", "false_positive"}
        closed = ts(f["closed_at"])
        if f["status"] == "open":
            assert closed is None, f["finding_id"]
        else:
            assert closed is not None and closed >= ts(f["opened_at"]), f["finding_id"]
        if f["status"] == "fixed":
            assert f["verified_by_retest"] is True      # the plan: a finding closes only after a retest confirms it
        assert ts(f["opened_at"]) <= NOW


def test_the_set_covers_every_case_the_kris_need():
    findings = load_findings()
    assert {f["status"] for f in findings} == {"open", "fixed", "false_positive"}
    assert {f["severity"] for f in findings} == {"critical", "high", "medium", "low"}
    assert any(f["severity"] == "critical" and f["status"] == "fixed" for f in findings)   # must not count as open
    ages = [(NOW - ts(f["opened_at"])).days for f in findings if f["status"] == "open"]
    assert any(a <= 7 for a in ages) and any(8 <= a <= 30 for a in ages)
    assert any(31 <= a <= 90 for a in ages) and any(a > 90 for a in ages)               # every ageing bucket


def test_the_sql_injection_attack_hits_an_endpoint_with_an_open_finding():
    """Spec 12.5: a real attack against an endpoint that already has an open finding gets a severity bonus."""
    open_by_asset = {(a, f["endpoint"]) for f in load_findings() if f["status"] == "open" for a in f["asset_ids"]}
    inc = next(i for i in load_incidents() if "sql_injection" in i["attack_families"])
    path = load_events("sql_injection")[0]["url"].split("?")[0]
    assert any((asset, path) in open_by_asset for asset in inc["affected_assets"])


# ---------- the KRI formulas on the fixtures (exact numbers) ----------
def test_kri_numbers_on_the_fixtures():
    findings = load_findings()
    assert [f["finding_id"] for f in open_findings(findings)] == [f"FND-00{i}" for i in range(1, 8)]
    assert open_critical_count(findings) == 1                                   # FND-001 only
    assert mean_time_to_remediate(findings) == {"mean_days": 16.0, "sample": 4}  # 20, 10, 20 and 14 days
    ageing = finding_ageing(findings, NOW)
    assert ageing["average_days"] == 38.1 and ageing["oldest_days"] == 104.0
    assert ageing["buckets"] == {"0-7": 2, "8-30": 2, "31-90": 2, ">90": 1}


# ---------- through the API ----------
def test_seeding_is_repeatable_and_removes_only_fixture_findings(fake_db):
    fake_db["findings"].insert_one({"finding_id": "REAL-1", "asset_ids": ["AST-001"], "severity": "high", "status": "open"})
    seed_findings.run()
    assert fake_db["findings"].count_documents({"source": "fixture"}) == 12
    assert fake_db["findings"].count_documents({"finding_id": "REAL-1"}) == 1


def test_kri_endpoint_shows_real_numbers_instead_of_no_data(fake_db):
    kris = {k["key"]: k for k in client.get("/kris").json()["kris"]}
    assert kris["open_critical_findings"]["status"] == "ok" and kris["open_critical_findings"]["value"] == 1
    assert kris["mean_time_to_remediate"]["value"] == 16.0
    assert kris["finding_ageing"]["status"] == "ok" and kris["finding_ageing"]["details"]["sample"] == 7


def test_asset_page_shows_its_findings(fake_db):
    web = client.get("/assets/AST-001/summary").json()
    assert {f["finding_id"] for f in web["findings"]} == {"FND-001", "FND-002", "FND-005", "FND-008", "FND-009"}
    assert web["counts"]["findings"] == 5
    assert {f["finding_id"] for f in client.get("/assets/AST-004/findings").json()} == {"FND-001", "FND-011"}
    assert [f["finding_id"] for f in client.get("/assets/AST-021/findings").json()] == ["FND-010"]
    assert all("source" in f for f in web["findings"])


def test_live_risk_counts_only_open_findings(fake_db):
    seed_risks.run()
    client.post("/risks/recalculate")
    web_risk = client.get("/risks/RSK-001").json()                    # SQL injection risk on AST-001 and AST-004
    assert web_risk["live_factors"]["finding_count"] == 3             # FND-001, 002, 005 (not fixed, not false positive)
    fake_db["findings"].update_many({}, {"$set": {"status": "fixed"}})
    client.post("/risks/recalculate")
    assert client.get("/risks/RSK-001").json()["live_factors"]["finding_count"] == 0
    assert client.get("/risks/RSK-001").json()["likelihood"] <= web_risk["likelihood"]
