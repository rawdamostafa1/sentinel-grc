"""Loads the Skyline assets into the database. Run: python seed.py

Safe to repeat. The seed owns the descriptive fields (name, owner, criticality...), but
hostnames and ip_addresses are written when an asset is first created, and later only to FILL
an empty list (so a new address added to seed_data.py reaches assets that already exist).
Addresses that were edited later (from the dashboard or PUT /assets/{id}) are never overwritten.
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
        for key, value in network.items():
            if value:   # fill only when the stored list is missing or empty
                col.update_one(
                    {"asset_id": asset["asset_id"], "$or": [{key: {"$exists": False}}, {key: []}, {key: None}]},
                    {"$set": {key: value}},
                )
    print(f"Seeded {len(SEED_ASSETS)} assets")


if __name__ == "__main__":
    run()
