"""سجل المخاطر (W3): إنشاء، scoring، عرض، تعديل، وقبول بتاريخ انتهاء."""
from fastapi import APIRouter, HTTPException, Query
from .database import get_assets, get_risks
from .risk_models import (AcceptanceRequest, Band, Risk, RiskCreate, RiskUpdate,
                          AnyStatus, AnyTreatment)
from .risk_scoring import score_fields, to_naive_utc, utcnow_naive

router = APIRouter(prefix="/risks", tags=["risks"])


def clean(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc


def expire_acceptances() -> None:
    """أي قبول انتهى تاريخه بيرجع الخطر open تلقائياً (acceptance_expired = true)."""
    now = utcnow_naive()
    get_risks().update_many(
        {"status": "accepted", "acceptance.expires_at": {"$lt": now}},
        {"$set": {"status": "open", "acceptance_expired": True, "updated_at": now}},
    )


def _check_assets(asset_ids: list[str]) -> None:
    unique = set(asset_ids)
    found = get_assets().count_documents({"asset_id": {"$in": list(unique)}})
    if found != len(unique):
        existing = {a["asset_id"] for a in get_assets().find({"asset_id": {"$in": list(unique)}})}
        raise HTTPException(422, f"unknown asset(s): {sorted(unique - existing)}")


def _next_id() -> str:
    numbers = [int(d["risk_id"][4:]) for d in get_risks().find({}, {"risk_id": 1})
               if str(d.get("risk_id", "")).startswith("RSK-")]
    return f"RSK-{(max(numbers, default=0) + 1):03d}"


def _get_or_404(risk_id: str) -> dict:
    doc = get_risks().find_one({"risk_id": risk_id})
    if not doc:
        raise HTTPException(404, "risk not found")
    return doc


@router.post("", response_model=Risk, status_code=201)
def create_risk(risk: RiskCreate):
    data = risk.model_dump(mode="json")
    _check_assets(data["asset_ids"])
    now = utcnow_naive()
    data.update(risk_id=_next_id(), base_likelihood=data["likelihood"], acceptance=None, acceptance_expired=False,
                created_at=now, updated_at=now)
    data.update(score_fields(data))
    get_risks().insert_one(data)
    return clean(data)


@router.get("", response_model=list[Risk])
def list_risks(asset_id: str | None = None, band: Band | None = None,
               status: AnyStatus | None = None, treatment: AnyTreatment | None = None,
               min_score: int | None = Query(default=None, ge=1, le=25)):
    expire_acceptances()
    query: dict = {}
    if asset_id:
        query["asset_ids"] = asset_id
    if band:
        query["inherent_band"] = band
    if status:
        query["status"] = status
    if treatment:
        query["treatment"] = treatment
    if min_score:
        query["inherent_score"] = {"$gte": min_score}
    return [clean(d) for d in get_risks().find(query).sort("inherent_score", -1)]


@router.get("/{risk_id}", response_model=Risk)
def get_risk(risk_id: str):
    expire_acceptances()
    return clean(_get_or_404(risk_id))


@router.put("/{risk_id}", response_model=Risk)
def update_risk(risk_id: str, changes: RiskUpdate):
    doc = _get_or_404(risk_id)
    updates = changes.model_dump(mode="json", exclude_none=True)
    if "asset_ids" in updates:
        _check_assets(updates["asset_ids"])
    doc.update(updates)
    if "likelihood" in updates:  # the analyst's value becomes the new baseline for W4
        doc["base_likelihood"] = updates["likelihood"]
    doc.update(score_fields(doc))
    doc["updated_at"] = utcnow_naive()
    get_risks().replace_one({"risk_id": risk_id}, doc)
    return clean(doc)


@router.post("/{risk_id}/accept", response_model=Risk)
def accept_risk(risk_id: str, body: AcceptanceRequest):
    """قبول الخطر: لازم owner وسبب وتاريخ انتهاء في المستقبل."""
    expires = to_naive_utc(body.expires_at)
    now = utcnow_naive()
    if expires <= now:
        raise HTTPException(422, "expires_at must be in the future")
    doc = _get_or_404(risk_id)
    doc.update(
        treatment="accept", status="accepted", acceptance_expired=False, updated_at=now,
        acceptance=dict(accepted_by=body.accepted_by, reason=body.reason,
                        expires_at=expires, accepted_at=now),
    )
    get_risks().replace_one({"risk_id": risk_id}, doc)
    return clean(doc)


@router.delete("/{risk_id}", status_code=204)
def delete_risk(risk_id: str):
    if get_risks().delete_one({"risk_id": risk_id}).deleted_count == 0:
        raise HTTPException(404, "risk not found")