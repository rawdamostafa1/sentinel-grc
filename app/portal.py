"""W8: GET /portal/summary, the only data the Client Portal needs, in one call.

Parts whose owner has not delivered data yet come back empty with a note, never invented:
  compliance  -> collection `compliance_snapshots` (Amira, Z2)
  reports     -> collection `reports` (Amira, Z7)
  actions     -> collection `actions` (Mohamed Osama, executor)
"""
from datetime import timedelta
from fastapi import APIRouter, Query
from .database import get_assets, get_db, get_incidents, get_risks
from .portal_scoring import (automatic_actions, compliance_overview, incident_summary, posture, top_risks)
from .risk_scoring import utcnow_naive
from .risks import expire_acceptances

router = APIRouter(prefix="/portal", tags=["client portal"])
HIDE = {"_id": 0, "expected": 0}


@router.get("/summary")
def portal_summary(days: int = Query(default=30, ge=1, le=365)):
    expire_acceptances()
    now = utcnow_naive()
    db = get_db()
    risks = list(get_risks().find({}, {"_id": 0}))
    names = {a["asset_id"]: a["name"] for a in get_assets().find({}, {"_id": 0, "asset_id": 1, "name": 1})}
    incidents = list(get_incidents().find({}, HIDE))
    snapshot = db["compliance_snapshots"].find_one({}, {"_id": 0}, sort=[("date", -1)])
    actions = list(db["actions"].find({}, {"_id": 0}))
    reports = [{"title": r.get("title") or r.get("name") or "Report", "created_at": r.get("created_at"),
                "url": r.get("url")} for r in db["reports"].find({}, {"_id": 0}).sort("created_at", -1).limit(10)]

    result = {
        "generated_at": now,
        "posture": posture(risks),
        "top_risks": top_risks(risks, names),
        "incidents": incident_summary(incidents, now - timedelta(days=days), days),
        "compliance": compliance_overview(snapshot),
        "automatic_actions": automatic_actions(actions),
        "reports": reports,
    }
    result["notes"] = [text for ok, text in (
        (result["posture"], "No active risks are recorded yet, so there is no posture score."),
        (result["compliance"]["percent"] is not None, "Compliance has not been calculated yet."),
        (result["automatic_actions"], "No completed automatic actions are recorded yet."),
        (reports, "No reports have been generated yet."),
    ) if not ok]
    return result
