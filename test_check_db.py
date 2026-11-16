"""Tests for check_db.py and seed_all.py."""
import mongomock
import pytest

import app.database as database
import check_db
import seed_all
from app.seed_data import SEED_ASSETS


@pytest.fixture()
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    yield database.get_db()
    database._client = old


def test_a_complete_database_has_no_problems(fake_db):
    seed_all.main(["--demo"])
    report = check_db.inspect_db(fake_db)
    assert report["problems"] == []
    assert report["assets"]["count"] == len(SEED_ASSETS) and report["assets"]["missing_from_database"] == []
    assert report["collections"]["incidents"]["fixture"] == 9 and report["controls"]["not_linked"] > 0
    assert "No problems found." in check_db.render(report)


def test_an_empty_database_says_what_to_run(fake_db):
    problems = check_db.inspect_db(fake_db)["problems"]
    assert any("python seed.py" in p for p in problems) and any("seed_controls" in p for p in problems)
    assert any("seed_risks" in p for p in problems)


def test_it_finds_the_mistakes_that_break_the_lookup(fake_db):
    seed_all.main([])
    col = fake_db["assets"]
    col.update_one({"asset_id": "AST-007"}, {"$set": {"ip_addresses": ["172.18.0.10"]}})     # same IP as skyline-web
    col.update_one({"asset_id": "AST-008"}, {"$set": {"ip_addresses": ["not-an-ip"]}})
    col.update_one({"asset_id": "AST-009"}, {"$set": {"criticality": 9}})
    col.update_one({"asset_id": "AST-026"}, {"$set": {"ip_addresses": ["172.18.0.50"]}})     # third-party with an address
    col.delete_one({"asset_id": "AST-012"})
    fake_db["risks"].update_one({"risk_id": "RSK-001"}, {"$set": {"asset_ids": ["AST-999"]}})
    text = "\n".join(check_db.inspect_db(fake_db)["problems"])
    for expected in ("172.18.0.10 is on more than one asset", "invalid IP address 'not-an-ip'", "invalid criticality 9",
                     "third-party asset VirusTotal API", "AST-012", "AST-999"):
        assert expected in text, expected


def test_changes_made_by_hand_are_reported_but_are_not_problems(fake_db):
    seed_all.main([])
    fake_db["assets"].update_one({"asset_id": "AST-001"}, {"$set": {"criticality": 4}})
    report = check_db.inspect_db(fake_db)
    assert report["assets"]["changed_since_seed"] == ["AST-001 skyline-web"] and report["problems"] == []


def test_the_report_never_contains_the_connection_string(fake_db, capsys):
    seed_all.main([])
    capsys.readouterr()
    check_db.main(["--json"])
    out = capsys.readouterr().out
    assert "mongodb" not in out.lower() and "password" not in out.lower()


def test_exit_code(fake_db, capsys):
    assert check_db.main([]) == 1
    seed_all.main([])
    assert check_db.main([]) == 0


def test_seed_all_is_repeatable_and_the_demo_can_be_removed(fake_db):
    seed_all.main(["--demo"])
    seed_all.main(["--demo"])
    assert fake_db["assets"].count_documents({}) == len(SEED_ASSETS) and fake_db["incidents"].count_documents({}) == 9
    seed_all.main(["--remove-demo"])
    assert fake_db["incidents"].count_documents({}) == 0 and fake_db["findings"].count_documents({}) == 0
    assert fake_db["assets"].count_documents({}) == len(SEED_ASSETS) and fake_db["risks"].count_documents({}) > 0
