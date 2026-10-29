"""W2: ربط الأصول بالحوادث والـ findings والمخاطر والـ controls.

مفيش جدول علاقات منفصل. كل نوع بيشيل الأصول المتأثرة بيها جواه:
  incidents -> affected_assets   (نفس اسم الحقل في سجل الحادثة بتاع Alaa)
  findings / risks / controls -> asset_ids
والـ endpoints هنا بتجمعهم لكل أصل.
"""
from fastapi import APIRouter, HTTPException
from .database import get_assets, get_incidents, get_findings, get_risks, get_controls
from .risks import expire_acceptances

router = APIRouter(prefix="/assets", tags=["asset relations"])

# (دالة الـ collection, اسم الحقل اللي فيه أرقام الأصول)
RELATED = {
    "incidents": (get_incidents, "affected_assets"),
    "findings": (get_findings, "asset_ids"),
    "risks": (get_risks, "asset_ids"),
    "controls": (get_controls, "asset_ids"),
}
# "expected" هي الإجابة الصح بتاعة التيستات، مايتعرضش في الـ API
HIDE = {"_id": 0, "expected": 0}


def _asset_or_404(asset_id: str) -> dict:
    doc = get_assets().find_one({"asset_id": asset_id})
    if not doc:
        raise HTTPException(404, "asset not found")
    doc.pop("_id", None)
    return doc


def _related(kind: str, asset_id: str) -> list[dict]:
    if kind == "risks":
        expire_acceptances()  # قبول منتهي يرجّع الخطر open قبل ما يتعرض
    collection, field = RELATED[kind]
    cursor = collection().find({field: asset_id}, HIDE)
    if kind == "incidents":
        cursor = cursor.sort("first_seen", -1)
    return list(cursor)


@router.get("/{asset_id}/summary")
def asset_summary(asset_id: str):
    """كل حاجة مرتبطة بالأصل في رد واحد (لصفحة الأصل)."""
    result = {"asset": _asset_or_404(asset_id)}
    for kind in RELATED:
        result[kind] = _related(kind, asset_id)
    result["counts"] = {kind: len(result[kind]) for kind in RELATED}
    return result


@router.get("/{asset_id}/incidents")
def asset_incidents(asset_id: str):
    _asset_or_404(asset_id)
    return _related("incidents", asset_id)


@router.get("/{asset_id}/findings")
def asset_findings(asset_id: str):
    _asset_or_404(asset_id)
    return _related("findings", asset_id)


@router.get("/{asset_id}/risks")
def asset_risks(asset_id: str):
    _asset_or_404(asset_id)
    return _related("risks", asset_id)


@router.get("/{asset_id}/controls")
def asset_controls(asset_id: str):
    _asset_or_404(asset_id)
    return _related("controls", asset_id)