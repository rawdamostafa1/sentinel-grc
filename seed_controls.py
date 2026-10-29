"""Loads Amira's control library (Z1) into the `controls` collection and links every control to assets (W2).
Run: python seed_controls.py        Safe to repeat: controls are updated by control_id, nothing is duplicated.

Why: GET /assets/{id}/controls reads the `controls` collection and looks for `asset_ids`.
Amira's control files (YAML, converted to JSON here so nothing has to be installed) have no asset link, only `platform_features` (which part of the platform covers the
control), so each control is linked to the assets that run those features (FEATURE_ASSETS below).
That table is a PROPOSAL: review it with Amira. Controls whose features have no asset (policy library,
risk register, compliance centre...) stay organisational controls with asset_ids = [].
"""
from datetime import date, datetime
import json
from pathlib import Path

CONTROLS_DIR = Path(__file__).parent / "controls_data"

# platform feature (Amira's feature_status.yaml) -> asset ids in app/seed_data.py
FEATURE_ASSETS = {
    "ai-agent": ["AST-010"],
    "tuning-agent": ["AST-010"],
    "ml-service": ["AST-009"],
    "sniffer": ["AST-013"],
    "log-shipper": ["AST-014"],
    "detector": ["AST-015"],
    "rule-engine": ["AST-015"],
    "correlation-engine": ["AST-016"],
    "case-management": ["AST-016"],
    "enrichment-service": ["AST-017"],
    "threat-intelligence": ["AST-017"],
    "pentest-module": ["AST-018"],
    "executor": ["AST-011"],
    "playbook-engine": ["AST-011"],
    "policy-guard": ["AST-011"],
    "haproxy-connector": ["AST-005", "AST-011"],
    "website-hooks": ["AST-001"],
    "website-mode-b": ["AST-001"],
    "rbac-auth": ["AST-003", "AST-019"],
    "report-generator": ["AST-020"],
    "audit-log": ["AST-008"],
    "backup-restore": ["AST-008"],
    "pipeline-health": ["AST-007"],
}
KEPT_FIELDS = ("framework", "function", "category", "category_id", "title", "description", "asset_class",
               "weight", "owner", "status", "maturity", "platform_features")


def asset_ids_for(features: list[str]) -> list[str]:
    return sorted({a for f in features for a in FEATURE_ASSETS.get(f, [])})


def load_control_files(directory: Path = CONTROLS_DIR) -> list[dict]:
    items = []
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"{path.name} is not a list of controls")
        items.extend(data)
    return items


def build_docs(items: list[dict]) -> list[dict]:
    """Amira's control items -> documents for the `controls` collection (no database needed)."""
    docs, seen = [], set()
    for item in items:
        if item["id"] in seen:
            raise ValueError(f"duplicate control id {item['id']}")
        seen.add(item["id"])
        doc = {key: item.get(key) for key in KEPT_FIELDS}
        doc["platform_features"] = list(item.get("platform_features") or [])
        review = item.get("review_date")
        doc["review_date"] = review.isoformat() if isinstance(review, (date, datetime)) else review
        doc["control_id"] = item["id"]
        doc["asset_ids"] = asset_ids_for(doc["platform_features"])
        docs.append(doc)
    return docs


def run(directory: Path = CONTROLS_DIR) -> int:
    from app.database import get_controls   # imported here so build_docs works without pymongo

    col = get_controls()
    col.create_index("control_id", unique=True)
    col.create_index("asset_ids")
    docs = build_docs(load_control_files(directory))
    for doc in docs:
        col.update_one({"control_id": doc["control_id"]}, {"$set": doc}, upsert=True)
    linked = sum(1 for d in docs if d["asset_ids"])
    print(f"Seeded {len(docs)} controls ({linked} linked to assets, {len(docs) - linked} organisational)")
    return len(docs)


if __name__ == "__main__":
    run()
