"""Loads the sample pentest findings (fixtures/findings.json) into the `findings` collection.
Run: python seed_findings.py

Why: Omar's pentest module is not delivering findings yet, but the KRIs (W5), the live risk (W4) and the
asset page (W2) need findings to be tested and demoed. These are clearly marked source="fixture".
Safe to repeat, and it only ever deletes the fixture findings, never real ones from the pentest module.
"""
from app.database import get_findings
from fixtures.loader import load_findings


def run() -> int:
    docs = [{**f, "source": "fixture"} for f in load_findings()]
    col = get_findings()
    col.create_index("finding_id", unique=True)
    col.create_index("asset_ids")
    col.delete_many({"source": "fixture"})
    col.insert_many(docs)
    print(f"Seeded {len(docs)} fixture findings")
    return len(docs)


if __name__ == "__main__":
    run()

