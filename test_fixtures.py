"""بيتأكد إن الـ fixtures سليمة ومترابطة. تشغيل: pytest test_fixtures.py"""
from app.seed_data import SEED_ASSETS
from fixtures.loader import (list_scenarios, load_events, load_alerts, load_incidents,
                             load_evidence, load_allowlist)

EVENT_FIELDS = {"event_id", "ts", "source", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "user", "session_id", "http_method", "url", "status", "user_agent", "event_type",
                "features", "raw", "tags", "tenant_id"}
WEIGHTS = dict(attack_type_weight=0.30, detection_confidence=0.20, asset_criticality=0.20,
               ip_reputation=0.15, recurrence=0.10, multi_stage_bonus=0.05)
GATE_CAP_MINUTES = {"G0": 0, "G1": 15, "G2": 360, "G3": 1440}


def _all_events():
    return {e["event_id"]: e for s in list_scenarios() for e in load_events(s)}


def test_events_follow_schema_and_ids_are_unique():
    seen = set()
    for s in list_scenarios():
        for e in load_events(s):
            assert set(e) == EVENT_FIELDS, f"{s}: wrong fields in {e['event_id']}"
            assert e["event_id"] not in seen
            seen.add(e["event_id"])


def test_alerts_point_to_real_events():
    events = _all_events()
    for a in load_alerts():
        assert all(i in events for i in a["event_ids"])


def test_incidents_are_linked_correctly():
    alerts = {a["alert_id"] for a in load_alerts()}
    events = _all_events()
    asset_ids = {a["asset_id"] for a in SEED_ASSETS}
    for inc in load_incidents():
        assert all(a in alerts for a in inc["alert_ids"])
        assert all(e in events for e in inc["event_ids"])
        assert all(a in asset_ids for a in inc["affected_assets"])
        assert load_evidence(inc["incident_id"])["ip"] == inc["src_ip"]


def test_severity_matches_the_formula():
    for inc in load_incidents():
        score = round(sum(WEIGHTS[k] * v for k, v in inc["severity_components"].items()), 4)
        assert score == inc["severity_score"]
        expected = "critical" if score >= .8 else "high" if score >= .6 else "medium" if score >= .4 else "low"
        assert inc["severity"] == expected


def test_allowlisted_ips_are_never_blocked():
    allow = {a["ip"] for a in load_allowlist()}
    for inc in load_incidents():
        if inc["src_ip"] in allow:
            assert "block_ip" in inc["expected"]["forbidden_actions"]


def test_expected_block_time_respects_the_gate():
    for inc in load_incidents():
        exp = inc["expected"]
        if "max_block_minutes" in exp:
            assert exp["max_block_minutes"] <= GATE_CAP_MINUTES[exp["max_gate"]]


def test_private_addresses_have_no_virustotal():
    for inc in load_incidents():
        if inc["src_ip"].startswith(("10.", "172.18.", "127.", "192.168.")):
            assert load_evidence(inc["incident_id"])["reputation"]["vt_available"] is False
