"""Looks at the database and reports what is in it and what looks wrong. Run: python check_db.py

Use it when something on the dashboard looks empty or strange, and send the output (it is safe to share: it prints
the database name, counts and asset names only, never the connection string or any password).
  python check_db.py            readable report
  python check_db.py --json     the same as JSON
Exit code 1 means it found problems.
"""
import ipaddress
import json
import sys
from collections import Counter

from app.database import MONGO_DB, get_db
from app.seed_data import SEED_ASSETS

COLLECTIONS = ("assets", "controls", "risks", "risk_history", "incidents", "alerts", "decisions", "actions", "findings",
               "policies", "policy_exceptions", "compliance_snapshots", "reports")
REFERENCES = {                      # collection -> field holding asset ids
    "risks": "asset_ids", "findings": "asset_ids", "controls": "asset_ids", "incidents": "affected_assets",
    "policy_exceptions": "asset_id",
}


def _as_list(value) -> list:
    return value if isinstance(value, list) else ([value] if value else [])


def inspect_db(db) -> dict:
    problems: list[str] = []
    report: dict = {"database": MONGO_DB}
    report["collections"] = {n: {"documents": db[n].count_documents({}), "fixture": db[n].count_documents({"source": "fixture"})}
                             for n in COLLECTIONS}

    assets = list(db["assets"].find({}, {"_id": 0}))
    seed = {a["asset_id"]: a for a in SEED_ASSETS}
    ids = Counter(a.get("asset_id") for a in assets)
    names = Counter(a.get("name") for a in assets)
    ips = Counter(ip for a in assets for ip in a.get("ip_addresses", []))
    no_ip = sorted(a["name"] for a in assets if not a.get("ip_addresses") and a.get("type") != "third-party")
    report["assets"] = {
        "count": len(assets), "expected_from_seed": len(seed),
        "missing_from_database": sorted(set(seed) - set(ids)), "not_in_seed": sorted(set(ids) - set(seed)),
        "without_ip_address": no_ip, "with_ip_address": sum(bool(a.get("ip_addresses")) for a in assets),
        "changed_since_seed": sorted(f"{a['asset_id']} {a['name']}" for a in assets if a["asset_id"] in seed and
                                     (a["name"] != seed[a["asset_id"]]["name"] or a["criticality"] != seed[a["asset_id"]]["criticality"])),
    }
    problems += [f"duplicate asset_id {k}" for k, v in ids.items() if v > 1]
    problems += [f"duplicate asset name {k}" for k, v in names.items() if v > 1]
    problems += [f"IP {k} is on more than one asset" for k, v in ips.items() if v > 1]
    problems += [f"asset {a['asset_id']} has an invalid criticality {a.get('criticality')}" for a in assets
                 if a.get("criticality") not in (1, 2, 3, 4, 5)]
    for a in assets:
        for ip in a.get("ip_addresses", []):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                problems.append(f"asset {a['asset_id']} has an invalid IP address {ip!r}")
        if a.get("type") == "third-party" and a.get("ip_addresses"):
            problems.append(f"third-party asset {a['name']} should not have an IP address in our network")
    if report["assets"]["missing_from_database"]:
        problems.append(f"{len(report['assets']['missing_from_database'])} seed assets are missing: run python seed.py")

    known = set(ids)
    orphans = {}
    for collection, field in REFERENCES.items():
        bad = sorted({a for doc in db[collection].find({}, {"_id": 0, field: 1}) for a in _as_list(doc.get(field)) if a not in known})
        orphans[collection] = bad
        if bad:
            problems.append(f"{collection} point to assets that do not exist: {bad}")
    report["orphan_asset_references"] = orphans

    controls = db["controls"].count_documents({})
    linked = db["controls"].count_documents({"asset_ids.0": {"$exists": True}})
    report["controls"] = {"count": controls, "linked_to_an_asset": linked, "not_linked": controls - linked}
    if controls == 0:
        problems.append("no controls: run python seed_controls.py")

    risks = list(db["risks"].find({}, {"_id": 0}))
    active = [r for r in risks if r.get("status") in ("open", "in_treatment", "accepted")]
    report["risks"] = {"count": len(risks), "active": len(active),
                       "never_recalculated": sum(1 for r in active if not r.get("last_recalculated")),
                       "without_base_likelihood": sum(1 for r in risks if not r.get("base_likelihood"))}
    if not risks:
        problems.append("no risks: run python seed_risks.py")
    report["problems"] = problems
    return report


def render(report: dict) -> str:
    lines = [f"Database: {report['database']}", "", "Collections (documents, of which demo fixtures):"]
    lines += [f"  {n:<22}{c['documents']:>6}  {c['fixture']:>4}" for n, c in report["collections"].items()]
    a = report["assets"]
    lines += ["", f"Assets: {a['count']} (seed has {a['expected_from_seed']}), {a['with_ip_address']} with an IP address",
              f"  missing from the database: {a['missing_from_database'] or 'none'}",
              f"  in the database but not in the seed: {a['not_in_seed'] or 'none'}",
              f"  changed since the seed (name or criticality): {a['changed_since_seed'] or 'none'}",
              f"  without an IP address: {', '.join(a['without_ip_address']) or 'none'}"]
    c, r = report["controls"], report["risks"]
    lines += ["", f"Controls: {c['count']} ({c['linked_to_an_asset']} linked to an asset, {c['not_linked']} not linked)",
              f"Risks: {r['count']} ({r['active']} active, {r['never_recalculated']} never recalculated)", ""]
    lines += ([f"PROBLEMS ({len(report['problems'])}):"] + [f"  - {p}" for p in report["problems"]]) if report["problems"] else ["No problems found."]
    return "\n".join(lines)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    report = inspect_db(get_db())
    print(json.dumps(report, indent=2) if "--json" in argv else render(report))
    return 1 if report["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
