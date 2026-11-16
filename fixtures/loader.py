"""طريقة سهلة يقرا بيها أي حد الـ fixtures في التيستات بتاعته.

مثال:
    from fixtures.loader import load_incident, load_events
    incident = load_incident("INC-001")
    events = load_events("brute_force")
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent


def _read(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_events(scenario: str) -> list[dict]:
    """scenario = اسم الملف في events/ من غير .json"""
    return _read(ROOT / "events" / f"{scenario}.json")


def list_scenarios() -> list[str]:
    return sorted(p.stem for p in (ROOT / "events").glob("*.json"))


def load_alerts() -> list[dict]:
    return _read(ROOT / "alerts.json")


def load_incidents() -> list[dict]:
    return _read(ROOT / "incidents.json")


def load_incident(incident_id: str) -> dict:
    return next(i for i in load_incidents() if i["incident_id"] == incident_id)


def load_evidence(incident_id: str) -> dict:
    bundles = _read(ROOT / "evidence_bundles.json")
    return next(b for b in bundles if b["incident_id"] == incident_id)


def load_allowlist() -> list[dict]:
    return _read(ROOT / "allowlist.json")


def load_findings() -> list[dict]:
    """Pentest findings in the Finding record shape (title, endpoint, CWE, OWASP, CVSS, severity, status, evidence)."""
    return _read(ROOT / "findings.json")


def load_finding(finding_id: str) -> dict:
    return next(f for f in load_findings() if f["finding_id"] == finding_id)


def load_decisions() -> list[dict]:
    """Agent decision records (Project Details 9.3 schema) for the 9 fixture incidents."""
    return _read(ROOT / "decisions.json")


def load_decision(incident_id: str) -> dict:
    return next(d for d in load_decisions() if d["incident_id"] == incident_id)


def load_actions() -> list[dict]:
    """Executed (or refused, or dry-run) actions, in the action record shape of Project Details 10.5."""
    return _read(ROOT / "actions.json")


def load_policies() -> list[dict]:
    return _read(ROOT / "policies.json")


def load_policy_exceptions() -> list[dict]:
    return _read(ROOT / "policy_exceptions.json")


def load_compliance_snapshot() -> dict:
    return _read(ROOT / "compliance_snapshot.json")
