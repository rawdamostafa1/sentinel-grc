"""W8: the formulas behind the Client Portal. Pure Python (no database, no FastAPI), easy to test.

Everything here is written for a non-technical reader (the customer), so the portal never shows
IP addresses, raw payloads or internal ids of attackers.

Team decisions (change them here):
  posture score = 100 * (1 - average residual risk score / 25), over the active risks
  labels        = Good >= 75 | Fair >= 50 | Needs attention >= 25 | At risk below that
"""
from datetime import datetime

from .risk_live_scoring import counted_incidents, parse_ts

ACTIVE_RISK_STATUS = ("open", "in_treatment", "accepted")   # same meaning as the W7 "active risks" tile
MAX_RISK_SCORE = 25
POSTURE_LABELS = ((75, "Good"), (50, "Fair"), (25, "Needs attention"), (0, "At risk"))
CLOSED_INCIDENT_STATUS = {"resolved", "closed", "false_positive"}
SEVERITIES = ("Critical", "High", "Medium", "Low")

# plain-language text for every action tool (never mention the target address)
ACTION_TEXT = {
    "block_ip": "Blocked a suspicious source from reaching your website",
    "rate_limit_ip": "Slowed down a source that was sending too many requests",
    "tarpit_ip": "Delayed a suspicious source so it could not keep attacking quickly",
    "lock_account": "Locked an account that showed suspicious activity",
    "revoke_sessions": "Signed out the sessions of a suspicious account",
    "add_waf_rule": "Added a protection rule against an attack pattern",
    "unblock_ip": "Removed a protection that was no longer needed",
}
SKIPPED_TOOLS = {"update_case", "notify", "verify_block"}   # internal bookkeeping, not protection
SUCCESS_WORDS = {"success", "succeeded", "ok", "executed", "completed", "done", "verified", "applied"}


def posture_label(score: int) -> str:
    for minimum, label in POSTURE_LABELS:
        if score >= minimum:
            return label
    return POSTURE_LABELS[-1][1]


def posture(risks: list[dict]):
    """None when there are no active risks (an empty register is not the same as 'safe')."""
    active = [r for r in risks if r.get("status") in ACTIVE_RISK_STATUS and isinstance(r.get("residual_score"), (int, float))]
    if not active:
        return None
    average = sum(r["residual_score"] for r in active) / len(active)
    score = max(0, min(100, round(100 * (1 - average / MAX_RISK_SCORE))))
    return {"score": score, "label": posture_label(score), "active_risks": len(active),
            "average_residual": round(average, 1)}


def top_risks(risks: list[dict], asset_names: dict[str, str], limit: int = 5) -> list[dict]:
    active = [r for r in risks if r.get("status") in ACTIVE_RISK_STATUS]
    active.sort(key=lambda r: (-r.get("residual_score", 0), -r.get("inherent_score", 0), r.get("risk_id", "")))
    return [{
        "risk_id": r.get("risk_id"), "title": r.get("title"), "band": r.get("residual_band"),
        "status": r.get("status"), "due_date": r.get("due_date"),
        "assets": [asset_names.get(a, a) for a in r.get("asset_ids", [])],
    } for r in active[:limit]]


def _severity(value) -> str | None:
    text = str(value or "").lower()
    return next((s for s in SEVERITIES if s.lower() == text), None)


def incident_summary(incidents: list[dict], cutoff: datetime, window_days: int) -> dict:
    """Real attacks in the window. False positives and authorised pentests are not counted."""
    counted = counted_incidents(incidents, cutoff)
    by_severity = {s: 0 for s in SEVERITIES}
    for inc in counted:
        severity = _severity(inc.get("severity"))
        if severity:
            by_severity[severity] += 1
    flagged = [i for i in counted if isinstance(i.get("handled_autonomously"), bool)]
    auto = round(100 * sum(1 for i in flagged if i["handled_autonomously"]) / len(flagged), 1) if flagged else None
    return {
        "window_days": window_days, "total": len(counted),
        "open": sum(1 for i in counted if str(i.get("status", "")).lower() not in CLOSED_INCIDENT_STATUS),
        "by_severity": by_severity, "handled_autonomously_percent": auto,
    }


def compliance_overview(snapshot: dict | None) -> dict:
    """Reads the newest snapshot saved by Amira's compliance.py (same shape as build_report())."""
    if not snapshot:
        return {"percent": None, "frameworks": {}, "as_of": None}
    frameworks = {name: data.get("percent") for name, data in (snapshot.get("frameworks") or {}).items()}
    values = [v for v in frameworks.values() if isinstance(v, (int, float))]
    return {"percent": round(sum(values) / len(values), 1) if values else None,
            "frameworks": frameworks, "as_of": snapshot.get("date")}


def _succeeded(action: dict) -> bool:
    result = action.get("result", action.get("status"))
    if isinstance(result, dict):
        if result.get("success") is True:
            return True
        result = result.get("status")
    return str(result or "").lower() in SUCCESS_WORDS


def automatic_actions(actions: list[dict], limit: int = 10) -> list[dict]:
    """Only actions that really happened. Dry runs, rejections and failures are left out."""
    shown = []
    for a in actions:
        tool = str(a.get("tool") or "")
        if tool in SKIPPED_TOOLS or a.get("dry_run") is True or not _succeeded(a):
            continue
        when = next((parse_ts(a.get(k)) for k in ("executed_at", "ts", "timestamp", "created_at") if parse_ts(a.get(k))), None)
        shown.append({"when": when.isoformat() if when else None,
                      "description": ACTION_TEXT.get(tool, "Took a protective action for your website"),
                      "undone": bool(a.get("rolled_back") or str(a.get("rollback_status", "")).lower() in {"done", "rolled_back"})})
    shown.sort(key=lambda s: s["when"] or "", reverse=True)
    return shown[:limit]
