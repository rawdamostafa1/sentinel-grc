"""Loads sample risks into the risk register (W3). Run: python seed_risks.py
Safe to repeat: it updates the same RSK ids instead of duplicating them,
it never deletes other risks, and it keeps status, treatment and acceptance
of risks that already exist (so manual edits are not lost).
These are example risks based on Skyline assets and the fixture incidents.
Review them with the team before using them in a demo."""
from app.database import get_risks
from app.risk_models import RiskCreate
from app.risk_scoring import score_fields, utcnow_naive

SAMPLE_RISKS = [
    ("RSK-001", dict(
        title="SQL injection in website search", asset_ids=["AST-001", "AST-004"],
        threat="External attacker injects SQL", vulnerability="String-built SQL query in search (mode A)",
        owner="Web Team", likelihood=4, impact=5, due_date="2026-11-30", review_date="2026-12-15",
        description="Booking and passenger data could be exposed.")),
    ("RSK-002", dict(
        title="Password guessing on the login page", asset_ids=["AST-003"],
        threat="Brute force / credential stuffing", vulnerability="No rate limit on /auth/login",
        owner="Web Team", likelihood=4, impact=4, due_date="2026-11-30",
        description="User accounts could be taken over.")),
    ("RSK-003", dict(
        title="Request flood against the website (DoS)", asset_ids=["AST-005", "AST-001"],
        threat="DoS / DDoS", vulnerability="Relies on HAProxy stick tables only",
        owner="Network Team", likelihood=3, impact=5, due_date="2026-12-10",
        description="The website could become unavailable.")),
    ("RSK-004", dict(
        title="Admin panel exposed to the internet", asset_ids=["AST-002"],
        threat="Unauthorised access", vulnerability="/admin is reachable from outside",
        owner="Web Team", likelihood=3, impact=4, due_date="2026-12-01",
        description="Full control if the login is guessed.")),
    ("RSK-005", dict(
        title="Compromise of the Sentinel database", asset_ids=["AST-008"],
        threat="Unauthorised access to data", vulnerability="Backups are not encrypted",
        owner="Platform Team", likelihood=2, impact=4, review_date="2027-01-15",
        description="Incident and investigation data could leak.")),
    ("RSK-006", dict(
        title="Duffel third-party service outage", asset_ids=["AST-006"],
        threat="Third-party downtime", vulnerability="No fallback for flight search",
        owner="Web Team", likelihood=3, impact=3, treatment="transfer",
        description="Flight search would stop working.")),
    ("RSK-007", dict(
        title="Event streams in Redis tampered with or lost", asset_ids=["AST-007"],
        threat="Attacker or faulty service writes to or wipes the event streams",
        vulnerability="Redis has no password inside the compose network",
        owner="Platform Team", likelihood=2, impact=3,
        description="Detection could miss attacks or act on fake events.")),
    ("RSK-008", dict(
        title="ML model misses attacks (drift or evasion)", asset_ids=["AST-009"],
        threat="Attackers change their traffic so the classifier labels it benign",
        vulnerability="Model is not retrained; drift is only monitored",
        owner="AI Team", likelihood=3, impact=3,
        description="Real attacks would not raise an ML alert.")),
    ("RSK-009", dict(
        title="Prompt injection against the AI agent", asset_ids=["AST-010"],
        threat="Attacker hides instructions in a user-agent or URL to trick the agent",
        vulnerability="The agent reads attacker-controlled text from logs",
        owner="AI Team", likelihood=3, impact=4,
        description="The agent could be pushed to a wrong verdict or action.")),
    ("RSK-010", dict(
        title="Automatic action blocks a legitimate address", asset_ids=["AST-011", "AST-005"],
        threat="Autonomous block hits an administrator or a real customer",
        vulnerability="Policy Guard allowlist may be incomplete",
        owner="SOAR Team", likelihood=2, impact=4,
        description="Legitimate users lose access to the website.")),
    ("RSK-011", dict(
        title="Unauthorised access to the SOC dashboard", asset_ids=["AST-012"],
        threat="Stolen or guessed analyst password",
        vulnerability="Demo passwords and optional multi-factor login",
        owner="Frontend Team", likelihood=3, impact=3,
        description="An attacker could undo actions or read incident data.")),
]


def run():
    col = get_risks()
    col.create_index("risk_id", unique=True)
    col.create_index("asset_ids")
    now = utcnow_naive()
    for risk_id, item in SAMPLE_RISKS:
        doc = RiskCreate(**item).model_dump(mode="json")
        doc.update(score_fields(doc))
        doc["base_likelihood"] = doc["likelihood"]  # W4 baseline
        doc["updated_at"] = now
        # set only when the risk is first created, never overwritten (manual edits are kept)
        insert_only = dict(
            status=doc.pop("status"),
            treatment=doc.pop("treatment"),
            auto_update=doc.pop("auto_update"),
            acceptance=None,
            acceptance_expired=False,
            created_at=now,
        )
        col.update_one({"risk_id": risk_id},
                       {"$set": doc, "$setOnInsert": insert_only},
                       upsert=True)
    print(f"Seeded {len(SAMPLE_RISKS)} risks")


if __name__ == "__main__":
    run()