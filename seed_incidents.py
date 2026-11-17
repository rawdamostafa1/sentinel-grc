
import sys

from app.database import get_incidents
from fixtures.loader import incidents_for_seeding


def run() -> int:
    # dates are moved to now and "expected" becomes the agent's verdict, see fixtures.loader.incidents_for_seeding
    docs = [{**d, "source": "fixture"} for d in incidents_for_seeding()]
    col = get_incidents()
    col.create_index("incident_id", unique=True)
    col.create_index("affected_assets")
    col.delete_many({"source": "fixture"})
    col.insert_many(docs)
    print(f"Seeded {len(docs)} fixture incidents")
    return len(docs)


def remove() -> int:
    deleted = get_incidents().delete_many({"source": "fixture"}).deleted_count
    print(f"Removed {deleted} fixture incidents")
    return deleted


if __name__ == "__main__":
    remove() if "--remove" in sys.argv else run()
