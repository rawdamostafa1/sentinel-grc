
import sys

from app.database import get_incidents
from fixtures.loader import load_incidents


def run() -> int:
    # "expected" is the right answer for tests (what the agent should decide), not part of the incident itself
    docs = [{**{k: v for k, v in i.items() if k != "expected"}, "source": "fixture"} for i in load_incidents()]
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
