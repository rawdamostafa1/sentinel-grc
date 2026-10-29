"""W7: 5x5 risk heatmap. Pure Python (no database, no FastAPI) so it is easy to test.

Rows are likelihood (1-5), columns are impact (1-5). Each cell lists the risks that sit there.
Closed risks are left out unless include_closed is true.
"""
from .risk_scoring import band_for

LEVELS = range(1, 6)
BANDS = ("Low", "Medium", "High", "Critical")


def risk_position(risk: dict, basis: str) -> tuple[int, int]:
    """(likelihood, impact) of a risk. Residual falls back to inherent when it is not set."""
    if basis == "residual":
        likelihood = risk.get("residual_likelihood") or risk["likelihood"]
        impact = risk.get("residual_impact") or risk["impact"]
    else:
        likelihood, impact = risk["likelihood"], risk["impact"]
    return likelihood, impact


def build_heatmap(risks: list[dict], basis: str = "inherent", include_closed: bool = False) -> dict:
    cells = {(l, i): [] for l in LEVELS for i in LEVELS}
    for risk in risks:
        if risk.get("status") == "closed" and not include_closed:
            continue
        cells[risk_position(risk, basis)].append(risk["risk_id"])
    bands = {band: 0 for band in BANDS}
    result = []
    for (likelihood, impact), ids in sorted(cells.items()):
        score = likelihood * impact
        band = band_for(score)
        bands[band] += len(ids)
        result.append({"likelihood": likelihood, "impact": impact, "score": score, "band": band,
                       "count": len(ids), "risk_ids": sorted(ids)})
    return {"basis": basis, "total": sum(c["count"] for c in result), "cells": result, "bands": bands}
