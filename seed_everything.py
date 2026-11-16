"""ONE command that fills everything, so no collection is left at 0.  Run: python seed_everything.py

What it does, in this order (safe to repeat):
  1. tags the 9 incidents that are already in Atlas (loaded by the old script) so the new seeders accept them;
  2. python seed_all.py --demo   -> assets, controls, risks + demo incidents, findings, alerts, decisions, actions,
                                    policies, policy exceptions, compliance snapshot;
  3. demo entries for `reports` (the Client Portal lists them);
  4. prints the check_db report so you can see the numbers.

Every demo document is marked source="fixture". The day real data arrives from the other owners, remove only the demo:
  python seed_everything.py --remove
"""
import sys
from datetime import datetime

import check_db
import seed_all
from app.database import get_db, get_incidents
from fixtures.loader import load_incidents

REPORTS = [
    dict(report_id="RPT-DEMO-001", title="Executive report (demo, week 42)", kind="executive",
         created_at=datetime(2026, 10, 19, 8, 0), url=None),
    dict(report_id="RPT-DEMO-002", title="Executive report (demo, week 43)", kind="executive",
         created_at=datetime(2026, 10, 26, 8, 0), url=None),
]


def tag_old_incidents() -> int:
    """Incidents loaded by the old seed script have no `source`. Tag the fixture ones; leave any other alone."""
    ids = [i["incident_id"] for i in load_incidents()]
    result = get_incidents().update_many({"incident_id": {"$in": ids}, "source": {"$exists": False}},
                                         {"$set": {"source": "fixture"}})
    if result.modified_count:
        print(f"Tagged {result.modified_count} old fixture incidents as source=fixture")
    return result.modified_count


def seed_reports() -> int:
    col = get_db()["reports"]
    col.create_index("report_id")
    col.delete_many({"source": "fixture"})
    col.insert_many([{**r, "source": "fixture"} for r in REPORTS])
    print(f"Seeded {len(REPORTS)} fixture reports")
    return len(REPORTS)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--remove" in argv:
        seed_all.main(["--remove-demo"])
        deleted = get_db()["reports"].delete_many({"source": "fixture"}).deleted_count
        print(f"Removed {deleted} fixture reports")
        return 0
    tag_old_incidents()
    seed_all.main(["--demo"])
    seed_reports()
    print()
    return check_db.main([])


if __name__ == "__main__":
    sys.exit(main())
