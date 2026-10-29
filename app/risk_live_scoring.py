"""W4: the live-risk formulas. Pure Python (no database, no FastAPI) so it is easy to test.

likelihood = analyst baseline + evidence points (from real incidents and open findings), max 5
impact     = from the criticality and data classification of the linked assets

Every number below is a team decision, not a rule from the spec. Change them here.
"""
from datetime import datetime
from .risk_scoring import to_naive_utc

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
UNKNOWN_SEVERITY_WEIGHT = 0.25

INCIDENT_FACTOR, INCIDENT_CAP = 0.5, 2.0   # points per unit of incident weight, and the cap
FINDING_FACTOR, FINDING_CAP = 0.5, 1.5
LINK_BONUS = 0.5   # attacks happened AND the asset has an open weakness

CLASS_SCORE = {"public": 1, "internal": 3, "confidential": 5}
CRITICALITY_SHARE = 0.7   # impact = 0.7 * criticality + 0.3 * data class

IGNORED_INCIDENT_STATUS = {"false_positive"}
CLOSED_FINDING_STATUS = {"fixed", "closed", "resolved", "remediated", "false_positive"}


def parse_ts(value):
    """datetime or ISO string -> naive UTC datetime. None if it cannot be read."""
    if isinstance(value, datetime):
        return to_naive_utc(value)
    if isinstance(value, str):
        try:
            return to_naive_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def is_authorized_test(inc: dict) -> bool:
    """Pentest traffic must not raise risk (spec 12.5: labelled authorized_test)."""
    if inc.get("authorized_test") is True:
        return True
    values = [inc.get("status"), inc.get("label"), inc.get("incident_type")]
    values += list(inc.get("labels") or []) + list(inc.get("tags") or [])
    return any(str(v).lower() == "authorized_test" for v in values if v)


def counted_incidents(incidents: list[dict], cutoff: datetime) -> list[dict]:
    """Unique incidents inside the time window, without false positives or authorized tests."""
    seen, result = set(), []
    for inc in incidents:
        key = inc.get("incident_id")
        if key in seen:
            continue
        seen.add(key)
        if str(inc.get("status", "")).lower() in IGNORED_INCIDENT_STATUS or is_authorized_test(inc):
            continue
        ts = parse_ts(inc.get("first_seen"))
        if ts is not None and ts < cutoff:
            continue
        result.append(inc)
    return result


def open_findings(findings: list[dict]) -> list[dict]:
    seen, result = set(), []
    for f in findings:
        key = f.get("finding_id")
        if key in seen:
            continue
        seen.add(key)
        if str(f.get("status", "open")).lower() not in CLOSED_FINDING_STATUS:
            result.append(f)
    return result


def _weight(item: dict) -> float:
    return SEVERITY_WEIGHT.get(str(item.get("severity", "")).lower(), UNKNOWN_SEVERITY_WEIGHT)


def evidence_points(incidents: list[dict], findings: list[dict]) -> dict:
    inc_pts = min(INCIDENT_CAP, INCIDENT_FACTOR * sum(_weight(i) for i in incidents))
    fnd_pts = min(FINDING_CAP, FINDING_FACTOR * sum(_weight(f) for f in findings))
    bonus = LINK_BONUS if incidents and findings else 0.0
    return {
        "incident_count": len(incidents), "finding_count": len(findings),
        "incident_points": round(inc_pts, 2), "finding_points": round(fnd_pts, 2),
        "link_bonus": bonus, "total_points": round(inc_pts + fnd_pts + bonus, 2),
    }


def live_likelihood(base: int, total_points: float) -> int:
    return max(1, min(5, int(base) + int(total_points + 0.5)))


def live_impact(assets: list[dict]):
    """None when there is no asset data (caller keeps the old impact)."""
    if not assets:
        return None
    crit = max(int(a.get("criticality", 1)) for a in assets)
    cls = max(CLASS_SCORE.get(a.get("data_classification"), 1) for a in assets)
    value = CRITICALITY_SHARE * crit + (1 - CRITICALITY_SHARE) * cls
    return max(1, min(5, int(value + 0.5)))