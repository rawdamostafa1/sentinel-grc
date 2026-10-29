"""W5: the KRI formulas. Pure Python (no database, no FastAPI) so they are easy to test.

Assumed shapes of other teams' data (confirm with them):
  findings  (Omar)   : finding_id, severity, status, opened_at|created_at, closed_at|fixed_at
  incidents (Alaa)   : labels, handled_autonomously (true/false)
"""
from datetime import datetime
from .risk_live_scoring import CLOSED_FINDING_STATUS, open_findings, parse_ts, is_authorized_test

OPENED_KEYS = ("opened_at", "created_at", "detected_at", "first_seen")
CLOSED_KEYS = ("closed_at", "fixed_at", "resolved_at", "retest_confirmed_at")
FIXED_STATUS = CLOSED_FINDING_STATUS - {"false_positive"}   # fixed for real, not "never a problem"
AGE_BUCKETS = (("0-7", 7), ("8-30", 30), ("31-90", 90))      # anything older goes to ">90"


def _first_ts(doc: dict, keys: tuple):
    for key in keys:
        ts = parse_ts(doc.get(key))
        if ts is not None:
            return ts
    return None


def _days(start: datetime, end: datetime) -> float:
    return (end - start).total_seconds() / 86400


def open_critical_count(findings: list[dict]) -> int:
    return sum(1 for f in open_findings(findings) if str(f.get("severity", "")).lower() == "critical")


def mean_time_to_remediate(findings: list[dict]):
    """Average days from opened to fixed. None when no finding has both dates."""
    durations = []
    for f in findings:
        if str(f.get("status", "")).lower() not in FIXED_STATUS:
            continue
        opened, closed = _first_ts(f, OPENED_KEYS), _first_ts(f, CLOSED_KEYS)
        if opened and closed and closed >= opened:
            durations.append(_days(opened, closed))
    if not durations:
        return None
    return {"mean_days": round(sum(durations) / len(durations), 1), "sample": len(durations)}


def finding_ageing(findings: list[dict], now: datetime):
    """How long the open findings have been open. None when open findings have no date."""
    open_list = open_findings(findings)
    if not open_list:
        return {"average_days": 0.0, "oldest_days": 0.0, "sample": 0,
                "buckets": {name: 0 for name, _ in AGE_BUCKETS} | {">90": 0}}
    ages = [_days(ts, now) for ts in (_first_ts(f, OPENED_KEYS) for f in open_list) if ts is not None]
    if not ages:
        return None
    buckets = {name: 0 for name, _ in AGE_BUCKETS} | {">90": 0}
    for age in ages:
        for name, limit in AGE_BUCKETS:
            if age <= limit:
                buckets[name] += 1
                break
        else:
            buckets[">90"] += 1
    return {"average_days": round(sum(ages) / len(ages), 1), "oldest_days": round(max(ages), 1),
            "sample": len(ages), "buckets": buckets}


def autonomy_rate(incidents: list[dict]):
    """% of incidents handled with no human action. None when no incident has the field."""
    eligible = [i for i in incidents
                if not is_authorized_test(i) and isinstance(i.get("handled_autonomously"), bool)]
    if not eligible:
        return None
    autonomous = sum(1 for i in eligible if i["handled_autonomously"])
    return {"percent": round(100 * autonomous / len(eligible), 1), "autonomous": autonomous,
            "total": len(eligible)}


def count_past(docs: list[dict], field: str, now: datetime) -> int:
    """How many documents have a date in `field` that is already in the past."""
    return sum(1 for d in docs if (ts := parse_ts(d.get(field))) is not None and ts < now)