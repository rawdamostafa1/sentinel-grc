"""منطق الـ scoring بتاع المخاطر (W3). بدون أي مكتبات خارجية عشان يتجرّب لوحده.

Score = likelihood x impact (1-25)
1-4 Low | 5-9 Medium | 10-16 High | 17-25 Critical   (Project Details، قسم 13.2)
"""
from datetime import datetime, timezone


def band_for(score: int) -> str:
    if score >= 17:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def score_fields(doc: dict) -> dict:
    """بيحسب inherent و residual. لو residual مش متحدد، بيساوي inherent."""
    inherent = doc["likelihood"] * doc["impact"]
    res_l = doc.get("residual_likelihood") or doc["likelihood"]
    res_i = doc.get("residual_impact") or doc["impact"]
    residual = res_l * res_i
    return {
        "inherent_score": inherent,
        "inherent_band": band_for(inherent),
        "residual_score": residual,
        "residual_band": band_for(residual),
    }


def utcnow_naive() -> datetime:
    """UTC من غير tzinfo. ده الشكل اللي MongoDB بيخزّنه ويقارنه."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt