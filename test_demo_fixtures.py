"""W10 + W5 tests: decisions, actions, policies, exceptions and the compliance snapshot fixtures, the demo seeder,
and the KRIs that read them. Run: python -m pytest test_demo_fixtures.py -v"""
import re
from datetime import datetime, timedelta

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
import seed_demo
import seed_findings
import seed_incidents
from app.kri_calc import RELEVANT_TECHNIQUES, attack_coverage
from app.main import app
from app.seed_data import SEED_ASSETS
from fixtures.loader import (load_actions, load_allowlist, load_compliance_snapshot, load_decisions,
                             load_incidents, load_policies, load_policy_exceptions)

client = TestClient(app)
ASSET_IDS = {a["asset_id"] for a in SEED_ASSETS}
GATE_ORDER = {"G0": 0, "G1": 1, "G2": 2, "G3": 3}
GATE_MIN_CONFIDENCE = {"G1": 0.60, "G2": 0.80, "G3": 0.90}
GATE_MAX_BLOCK = {"G0": 0, "G1": 15, "G2": 360, "G3": 1440}
WRITE_TOOLS = {"block_ip", "rate_limit_ip", "tarpit_ip", "lock_account", "add_waf_rule", "update_case", "notify"}
INCIDENTS = {i["incident_id"]: i for i in load_incidents()}


@pytest.fixture()
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    database.get_db()["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    yield database.get_db()
    database._client = old


def ts(value):
    return datetime.fromisoformat(value.replace("Z", ""))


def evidence_types(decision):
    return {e.split(":")[0] if ":" in e else e.split()[0] for e in decision["evidence"]}


# ---------- decisions (Project Details 9.3 and the confidence gates of 9.6) ----------
def test_there_is_one_decision_per_incident_in_the_schema_of_the_spec():
    decisions = load_decisions()
    assert [d["incident_id"] for d in decisions] == sorted(INCIDENTS)
    for d in decisions:
        assert d["verdict"] in {"true_positive", "false_positive", "uncertain"}
        assert d["severity"] in {"critical", "high", "medium", "low"} and 0 <= d["confidence"] <= 1
        assert d["evidence"] and d["reasoning"] and d["path"] in {"agent", "fallback"}
        assert len(re.findall(r"[.!?](?:\s|$)", d["reasoning"])) <= 5          # "five sentences maximum"
        assert d["mitre"] == INCIDENTS[d["incident_id"]]["techniques"]
        assert (d["prompt_version"] is None) == (d["path"] == "fallback")        # a fallback decision has no model


def test_each_decision_matches_the_expected_answer_of_its_incident():
    for d in load_decisions():
        expected = INCIDENTS[d["incident_id"]]["expected"]
        tools = [a["tool"] for a in d["actions"]]
        assert d["verdict"] == expected["verdict"], d["incident_id"]
        assert GATE_ORDER[d["gate"]] <= GATE_ORDER[expected["max_gate"]]
        assert set(expected["must_include_actions"]) <= set(tools)
        assert not set(tools) & set(expected["forbidden_actions"])
        for a in d["actions"]:
            if a["tool"] == "block_ip":
                ttl = a["args"]["ttl_minutes"]
                assert ttl <= expected.get("max_block_minutes", 0) and ttl >= expected.get("min_block_minutes", 0)


def test_decisions_respect_the_confidence_gates():
    for d in load_decisions():
        gate = d["gate"]
        if gate == "G0":
            assert all(a["tool"] in {"update_case", "notify"} for a in d["actions"])
            continue
        assert d["verdict"] == "true_positive" and d["confidence"] >= GATE_MIN_CONFIDENCE[gate], d["incident_id"]
        if gate in ("G2", "G3"):
            assert len(evidence_types(d)) >= 2, d["incident_id"]
        if gate == "G3":
            assert d["severity"] == "critical" or INCIDENTS[d["incident_id"]]["src_ip"] == "203.0.113.15"
        for a in d["actions"]:
            if a["tool"] == "block_ip":
                assert a["args"]["ttl_minutes"] <= GATE_MAX_BLOCK[gate]
            assert a["tool"] in WRITE_TOOLS


# ---------- actions (Project Details 10.5) ----------
def test_action_records_are_consistent_with_decisions_and_incidents():
    decisions = {d["decision_id"]: d for d in load_decisions()}
    ids = set()
    for a in load_actions():
        assert a["action_id"] not in ids
        ids.add(a["action_id"])
        d = decisions[a["decision_id"]]
        assert a["incident_id"] == d["incident_id"] and a["actor"] == "agent"
        assert a["result"] in {"success", "rejected", "failed"} and isinstance(a["dry_run"], bool)
        if a["result"] == "rejected":
            assert a["reason"] and a["verification"] is None
        if a["result"] == "success" and not a["dry_run"]:
            assert a["verification"] == {"checked": True, "confirmed": True}
        if a["expires_at"]:
            ttl = a["args"]["ttl_minutes"]
            assert ts(a["expires_at"]) == ts(a["executed_at"]) + timedelta(minutes=ttl)


def test_nothing_on_the_allowlist_was_ever_blocked_successfully():
    allow = {e["ip"] for e in load_allowlist()}
    for a in load_actions():
        if a["tool"] == "block_ip" and a["args"].get("ip") in allow:
            assert a["result"] == "rejected" and a["reason"] == "allowlisted"


def test_the_set_has_a_rolled_back_a_refused_and_a_dry_run_action():
    actions = load_actions()
    assert any(a["rolled_back"] and a["rollback_status"] == "done" for a in actions)
    assert any(a["result"] == "rejected" for a in actions) and any(a["dry_run"] for a in actions)


# ---------- policies, exceptions, compliance ----------
def test_policies_and_exceptions_have_what_the_kris_need():
    policies = load_policies()
    assert len({p["policy_id"] for p in policies}) == len(policies) == 5
    for p in policies:
        assert {"policy_id", "name", "version", "owner", "status", "review_date"} <= set(p)
        ts(p["review_date"] + "T00:00:00")
    assert sum(ts(p["review_date"] + "T00:00:00") < datetime(2026, 10, 22) for p in policies) == 2
    assert next(p for p in policies if p["policy_id"] == "POL-001")["parameters"] == {"block_hours": 24}   # policy drives the playbook
    ids = {p["policy_id"] for p in policies}
    for e in load_policy_exceptions():
        assert e["policy_id"] in ids and e["asset_id"] in ASSET_IDS and e["reason"] and e["approved_by"]


def test_compliance_snapshot_has_the_shape_of_amiras_report():
    snap = load_compliance_snapshot()
    assert set(snap["frameworks"]) == {"NIST_CSF_2.0", "CIS_V8_1", "ISO27001_2022", "OWASP_TOP10_2025"}
    assert all(0 <= f["percent"] <= 100 for f in snap["frameworks"].values())


# ---------- the demo seeder ----------
def test_demo_seeder_loads_everything_and_is_repeatable(fake_db):
    first = seed_demo.run()
    assert first == {"alerts": 12, "decisions": 9, "actions": 9, "policies": 5, "policy_exceptions": 3,
                     "compliance_snapshots": 1}
    seed_demo.run()
    for name, count in first.items():
        assert fake_db[name].count_documents({}) == count and fake_db[name].count_documents({"source": "fixture"}) == count


def test_removing_demo_data_never_touches_real_documents(fake_db):
    seed_incidents.run()
    seed_findings.run()
    seed_demo.run()
    real = {"alerts": "A-REAL", "incidents": "I-REAL", "findings": "F-REAL", "actions": "X-REAL"}
    for collection, key in real.items():
        fake_db[collection].insert_one({"_real": key})
    removed = seed_demo.remove()
    assert removed["incidents"] == 9 and removed["findings"] == 12 and removed["alerts"] == 12
    for collection, key in real.items():
        assert fake_db[collection].count_documents({"_real": key}) == 1
        assert fake_db[collection].count_documents({"source": "fixture"}) == 0


def test_the_incident_seeder_no_longer_wipes_other_peoples_incidents(fake_db):
    fake_db["incidents"].insert_many([{"incident_id": "REAL-1"}, {"incident_id": "REAL-2"}])
    seed_incidents.run()
    seed_incidents.run()
    assert fake_db["incidents"].count_documents({}) == 11 and fake_db["incidents"].count_documents({"incident_id": "REAL-1"}) == 1
    assert fake_db["incidents"].find_one({"incident_id": "INC-001"}).get("expected") is None


# ---------- the KRIs on the demo data ----------
def test_every_kri_has_a_value_when_the_demo_data_is_loaded(fake_db):
    seed_incidents.run()
    seed_findings.run()
    seed_demo.run()
    kris = {k["key"]: k for k in client.get("/kris").json()["kris"]}
    assert {k: v["status"] for k, v in kris.items() if v["status"] != "ok"} == {}
    assert kris["open_critical_findings"]["value"] == 1
    assert kris["mean_time_to_remediate"]["value"] == 16.0
    assert kris["autonomy_rate"]["value"] == 75.0                    # 6 of the 8 real incidents (the pentest is left out)
    assert kris["attack_coverage"]["value"] == 55.6
    assert kris["policy_review_overdue"]["value"] == 2
    assert kris["expired_exceptions"]["value"] == 1 and kris["expired_exceptions"]["details"]["policy_exceptions"] == 1


def test_attack_coverage_formula():
    assert attack_coverage([]) is None
    alerts = [{"techniques": ["T1110.001"]}, {"techniques": ["T1190", "T9999"]}, {"techniques": []}, {}]
    result = attack_coverage(alerts)
    assert result["covered"] == ["T1110", "T1190"] and result["percent"] == round(100 * 2 / len(RELEVANT_TECHNIQUES), 1)
    assert "T1498" in result["uncovered"] and result["relevant"] == 9
    assert attack_coverage([{"techniques": list(RELEVANT_TECHNIQUES)}])["percent"] == 100.0


def test_coverage_kri_says_no_data_without_alerts(fake_db):
    kri = {k["key"]: k for k in client.get("/kris").json()["kris"]}["attack_coverage"]
    assert kri["status"] == "no_data" and kri["value"] is None and "Alaa" in kri["note"]
