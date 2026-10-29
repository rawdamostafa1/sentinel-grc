"""W7: GET /risks/heatmap. The data behind the 5x5 heatmap on the Risk Register page."""
from typing import Literal
from fastapi import APIRouter
from .database import get_risks
from .heatmap_calc import build_heatmap
from .risks import expire_acceptances

router = APIRouter(prefix="/risks", tags=["heatmap"])


@router.get("/heatmap")
def risk_heatmap(basis: Literal["inherent", "residual"] = "inherent",
                 asset_id: str | None = None, include_closed: bool = False):
    """25 cells (likelihood x impact) with the risk ids inside each, plus totals per band."""
    expire_acceptances()  # an expired acceptance puts the risk back on the map
    query = {"asset_ids": asset_id} if asset_id else {}
    risks = list(get_risks().find(query, {"_id": 0}))
    return build_heatmap(risks, basis, include_closed)
