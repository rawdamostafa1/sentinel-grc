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
