from app.seed_data import SEED_ASSETS
from fixtures.loader import load_incidents, load_evidence

seed = {a["asset_id"]: a for a in SEED_ASSETS}
for i in load_incidents():
    fx = load_evidence(i["incident_id"])["asset"]
    s = seed[fx["asset_id"]]
    ok = s["name"] == fx["name"] and s["criticality"] == fx["criticality"]
    print(i["incident_id"], fx["asset_id"], "OK" if ok else f"MISMATCH fixtures={fx} seed={s['name']}/{s['criticality']}")