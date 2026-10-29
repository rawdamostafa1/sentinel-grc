"""Loads the Skyline assets into the database. Run: python seed.py

Safe to repeat. The seed owns the descriptive fields (name, owner, criticality...), but
hostnames and ip_addresses are only written when an asset is first created, so addresses
that were edited later (from the dashboard or PUT /assets/{id}) are never wiped.
"""
from app.database import get_assets
from app.models import AssetCreate
from app.seed_data import SEED_ASSETS

NETWORK_FIELDS = ("hostnames", "ip_addresses")


def run():
    col = get_assets()
    col.create_index("asset_id", unique=True)
    col.create_index("name", unique=True)
    col.create_index("ip_addresses")
    col.create_index("hostnames")
    for item in SEED_ASSETS:
        asset = AssetCreate(**item).model_dump()
        network = {key: asset.pop(key) for key in NETWORK_FIELDS}
        col.update_one(
            {"asset_id": asset["asset_id"]},
            {"$set": asset, "$setOnInsert": {**network, "last_seen": None}},
            upsert=True,
        )
    print(f"Seeded {len(SEED_ASSETS)} assets")


if __name__ == "__main__":
    run()
