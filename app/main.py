"""الـ API بتاع الأصول (W1). بيشتغل بـ: uvicorn app.main:app --reload"""
import uuid
from fastapi import FastAPI, HTTPException, Query
from .database import get_assets
from .models import Asset, AssetCreate, AssetUpdate, now_utc
from .relations import router as relations_router
from .heatmap import router as heatmap_router
from .risks import router as risks_router
from .risk_live import router as live_router
from .kris import router as kris_router

app = FastAPI(title="Sentinel GRC - Assets")
# W7: /risks/heatmap must be registered BEFORE risks_router, otherwise /risks/{risk_id} catches it
app.include_router(heatmap_router)
app.include_router(risks_router)  # W3: /risks
app.include_router(live_router)  # W4: /risks/recalculate
app.include_router(kris_router)  # W5: /kris
app.include_router(relations_router)  # W2: /assets/{id}/summary وغيره


def clean(doc: dict) -> dict:
    """بنشيل _id بتاع Mongo عشان الرد يبقى نضيف."""
    doc.pop("_id", None)
    return doc


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/assets", response_model=Asset, status_code=201)
def create_asset(asset: AssetCreate):
    data = asset.model_dump()
    data["asset_id"] = data["asset_id"] or f"AST-{uuid.uuid4().hex[:6]}"
    if get_assets().find_one({"$or": [{"asset_id": data["asset_id"]}, {"name": data["name"]}]}):
        raise HTTPException(409, "asset already exists")
    data["last_seen"] = None
    get_assets().insert_one(data)
    return clean(data)


@app.get("/assets", response_model=list[Asset])
def list_assets(type: str | None = None, exposure: str | None = None,
                min_criticality: int | None = Query(default=None, ge=1, le=5)):
    query: dict = {}
    if type:
        query["type"] = type
    if exposure:
        query["exposure"] = exposure
    if min_criticality:
        query["criticality"] = {"$gte": min_criticality}
    return [clean(d) for d in get_assets().find(query).sort("asset_id", 1)]


# مهم: /assets/lookup لازم تيجي قبل /assets/{asset_id}
@app.get("/assets/lookup", response_model=Asset)
def lookup_asset(ip: str | None = None, name: str | None = None):
    """ده اللي Alaa وHabiba هينادوا عليه: ابحث بالـ IP أو بالاسم."""
    if not ip and not name:
        raise HTTPException(400, "send ip or name")
    if ip:
        query = {"ip_addresses": ip}
    else:
        query = {"$or": [{"name": name}, {"hostnames": name}]}
    doc = get_assets().find_one(query)
    if not doc:
        raise HTTPException(404, "no asset found")
    return clean(doc)


@app.get("/assets/{asset_id}", response_model=Asset)
def get_asset(asset_id: str):
    doc = get_assets().find_one({"asset_id": asset_id})
    if not doc:
        raise HTTPException(404, "asset not found")
    return clean(doc)


@app.put("/assets/{asset_id}", response_model=Asset)
def update_asset(asset_id: str, changes: AssetUpdate):
    updates = changes.model_dump(exclude_none=True)
    if updates:
        get_assets().update_one({"asset_id": asset_id}, {"$set": updates})
    doc = get_assets().find_one({"asset_id": asset_id})
    if not doc:
        raise HTTPException(404, "asset not found")
    return clean(doc)


@app.post("/assets/{asset_id}/seen", response_model=Asset)
def mark_seen(asset_id: str):
    """بيحدّث last_seen لوقت دلوقتي."""
    get_assets().update_one({"asset_id": asset_id}, {"$set": {"last_seen": now_utc()}})
    doc = get_assets().find_one({"asset_id": asset_id})
    if not doc:
        raise HTTPException(404, "asset not found")
    return clean(doc)


@app.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: str):
    if get_assets().delete_one({"asset_id": asset_id}).deleted_count == 0:
        raise HTTPException(404, "asset not found")