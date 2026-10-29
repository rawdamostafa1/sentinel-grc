"""W5: Key Risk Indicators. GET /kris returns every KRI from section 13.8 of the spec.

A KRI whose data does not exist yet comes back with status "no_data" and a note that says
who owns the data. Nothing is invented.
"""
from fastapi import APIRouter
from .database import get_db, get_findings, get_incidents, get_risks
from .kri_calc import (autonomy_rate, count_past, finding_ageing, mean_time_to_remediate,
                       open_critical_count)
from .risk_scoring import utcnow_naive
from .risks import expire_acceptances

router = APIRouter(tags=["kris"])
HIDE = {"_id": 0, "expected": 0}
ACTIVE = ("open", "in_treatment")


def kri(key, label, value, unit, source, note="", details=None):
    return {"key": key, "label": label, "value": value, "unit": unit,
            "status": "no_data" if value is None else "ok",
            "source": source, "note": note, "details": details or {}}


@router.get("/kris")
def get_kris():
    expire_acceptances()
    now = utcnow_naive()
    findings = list(get_findings().find({}, HIDE))
    incidents = list(get_incidents().find({}, HIDE))
    risks = list(get_risks().find({}, {"_id": 0}))
    policies = list(get_db()["policies"].find({}, {"_id": 0}))
    exceptions = list(get_db()["policy_exceptions"].find({}, {"_id": 0}))

    no_findings = "No findings in the database yet (pentest module, Omar)."
    mttr = mean_time_to_remediate(findings) if findings else None
    ageing = finding_ageing(findings, now) if findings else None
    auto = autonomy_rate(incidents)

    expired_risks = get_risks().count_documents({"acceptance_expired": True})
    expired_policy = count_past(exceptions, "expires_at", now)
    active = [r for r in risks if r.get("status") in ACTIVE]

    return {"generated_at": now, "kris": [
        kri("open_critical_findings", "Open critical findings",
            open_critical_count(findings) if findings else None, "findings",
            "findings (Omar)", "" if findings else no_findings),
        kri("mean_time_to_remediate", "Mean time to remediate",
            mttr["mean_days"] if mttr else None, "days", "findings (Omar)",
            "" if mttr else "Needs fixed findings with opened and closed dates.",
            {"sample": mttr["sample"]} if mttr else None),
        kri("finding_ageing", "Open finding ageing (average)",
            ageing["average_days"] if ageing else None, "days", "findings (Omar)",
            "" if ageing else (no_findings if not findings else "Open findings have no opened date."),
            ageing),
        kri("autonomy_rate", "Incidents handled autonomously",
            auto["percent"] if auto else None, "%", "incidents (Alaa) + agent (Habiba)",
            "" if auto else "No incident has the handled_autonomously field yet.",
            {k: auto[k] for k in ("autonomous", "total")} if auto else None),
        kri("attack_coverage", "ATT&CK detection coverage", None, "%", "coverage analysis (Ariam)",
            "Waiting for Ariam's coverage analysis (R7)."),
        kri("expired_exceptions", "Expired exceptions", expired_risks + expired_policy, "exceptions",
            "risk acceptances (Rawda) + policy exceptions (Amira)",
            "Policy exceptions count only when Amira's collection exists.",
            {"risk_acceptances": expired_risks, "policy_exceptions": expired_policy}),
        kri("policy_review_overdue", "Policies overdue for review",
            count_past(policies, "review_date", now) if policies else None, "policies",
            "policy library (Amira)", "" if policies else "No policies in the database yet (Amira, Z4)."),
        # extra KRIs computed from the risk register itself
        kri("critical_risks", "Active critical risks",
            sum(1 for r in active if r.get("inherent_band") == "Critical"), "risks",
            "risk register (Rawda)", "Extra KRI, not in the spec list."),
        kri("overdue_risks", "Active risks past their due date",
            count_past(active, "due_date", now), "risks", "risk register (Rawda)",
            "Extra KRI, not in the spec list."),
    ]}