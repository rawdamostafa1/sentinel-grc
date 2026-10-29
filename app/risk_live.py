"""W4: live risk calculation. The risk moves when attacks and findings move.

Run it with  POST /risks/recalculate  (later a scheduler can call recalculate_all()).
Every run saves one snapshot per risk in `risk_history` for the trend chart.
Skipped: accepted/closed risks, and risks with auto_update = false.
"""
from datetime import timedelta
from fastapi import APIRouter, HTTPException, Query
from .database import get_assets, get_findings, get_incidents, get_risk_history, get_risks
from .risk_live_scoring import (counted_incidents, evidence_points, live_impact,
                                live_likelihood, open_findings)
from .risk_scoring import score_fields, utcnow_naive
from .risks import expire_acceptances

router = APIRouter(tags=["live risk"])
DEFAULT_DAYS = 30
HIDE = {"_id": 0, "expected": 0}


def recalculate_all(days: int = DEFAULT_DAYS) -> dict:
    expire_acceptances()
    now = utcnow_naive()
    cutoff = now - timedelta(days=days)
    summary = {"checked": 0, "changed": 0, "skipped": 0, "window_days": days}
    for doc in list(get_risks().find({})):
        if doc.get("auto_update", True) is False or doc.get("status") in ("accepted", "closed"):
            summary["skipped"] += 1
            continue
        ids = doc["asset_ids"]
        assets = list(get_assets().find({"asset_id": {"$in": ids}}))
        incidents = counted_incidents(
            list(get_incidents().find({"affected_assets": {"$in": ids}}, HIDE)), cutoff)
        findings = open_findings(list(get_findings().find({"asset_ids": {"$in": ids}}, HIDE)))
        points = evidence_points(incidents, findings)

        base = doc.get("base_likelihood") or doc["likelihood"]
        likelihood = live_likelihood(base, points["total_points"])
        impact = live_impact(assets) or doc["impact"]
        merged = {**doc, "likelihood": likelihood, "impact": impact}
        scores = score_fields(merged)
        changed = (likelihood, impact) != (doc["likelihood"], doc["impact"])

        get_risks().update_one({"risk_id": doc["risk_id"]}, {"$set": {
            "likelihood": likelihood, "impact": impact, "base_likelihood": base,
            "live_factors": {**points, "window_days": days},
            "last_recalculated": now,
            "updated_at": now if changed else doc.get("updated_at", now),
            **scores,
        }})
        get_risk_history().insert_one({
            "risk_id": doc["risk_id"], "ts": now, "likelihood": likelihood, "impact": impact,
            "base_likelihood": base, "incident_count": points["incident_count"],
            "finding_count": points["finding_count"], **scores,
        })
        summary["checked"] += 1
        summary["changed"] += int(changed)
    return summary


@router.post("/risks/recalculate")
def recalculate(days: int = Query(default=DEFAULT_DAYS, ge=1, le=3650)):
    """Recalculate likelihood and impact of every open risk from real incidents and findings."""
    return recalculate_all(days)


@router.get("/risks/{risk_id}/history")
def risk_history(risk_id: str):
    """Snapshots over time (for the trend chart), oldest first."""
    if not get_risks().find_one({"risk_id": risk_id}):
        raise HTTPException(404, "risk not found")
    return list(get_risk_history().find({"risk_id": risk_id}, {"_id": 0}).sort("ts", 1))