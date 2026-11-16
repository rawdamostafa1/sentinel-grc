"""Demo data for the collections that OTHER owners fill in, so the KRIs (W5), the live risk (W4) and the
Client Portal (W8) can be tested and shown without waiting for them.

  alerts, decisions, actions   -> Alaa's pipeline and the agent / executor (Habiba, Mohamed Osama)
  policies, policy_exceptions  -> Amira (Z4)
  compliance_snapshots         -> Amira (Z2)

Every document is marked source="fixture", and this script only ever deletes fixture documents.
  python seed_demo.py            load them
  python seed_demo.py --remove   remove only the fixture documents (also fixture incidents and findings)
Run python seed_incidents.py and python seed_findings.py for the incidents and findings.
"""
import sys

from app.database import get_db
from fixtures.loader import (load_actions, load_alerts, load_compliance_snapshot, load_decisions, load_policies,
                             load_policy_exceptions)

DEMO = {                       # collection -> (loader, unique key)
    "alerts": (load_alerts, "alert_id"),
    "decisions": (load_decisions, "decision_id"),
    "actions": (load_actions, "action_id"),
    "policies": (load_policies, "policy_id"),
    "policy_exceptions": (load_policy_exceptions, "exception_id"),
    "compliance_snapshots": (lambda: [load_compliance_snapshot()], "date"),
}
OTHER_FIXTURES = ("incidents", "findings")


def run() -> dict[str, int]:
    db, counts = get_db(), {}
    for name, (loader, key) in DEMO.items():
        docs = [{**d, "source": "fixture"} for d in loader()]
        db[name].create_index(key)
        db[name].delete_many({"source": "fixture"})
        db[name].insert_many(docs)
        counts[name] = len(docs)
    print("Seeded " + ", ".join(f"{n} {name}" for name, n in counts.items()))
    return counts


def remove() -> dict[str, int]:
    db = get_db()
    removed = {name: db[name].delete_many({"source": "fixture"}).deleted_count for name in (*DEMO, *OTHER_FIXTURES)}
    print("Removed fixture documents: " + ", ".join(f"{n} {name}" for name, n in removed.items()))
    return removed


if __name__ == "__main__":
    remove() if "--remove" in sys.argv else run()
