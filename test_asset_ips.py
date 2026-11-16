"""Do the assets and their addresses agree with the fixtures (W10) and the team's allowlist?
Runs on a fake database. Run: python -m pytest test_asset_ips.py -v"""
import ipaddress

import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.seed_data import SEED_ASSETS
from fixtures.loader import list_scenarios, load_allowlist, load_events, load_incidents

client = TestClient(app)
LAB_NET = ipaddress.ip_network("172.18.0.0/16")
NOT_ASSETS = {"127.0.0.1", "10.0.0.1", "8.8.8.8", "1.1.1.1"}      # loopback, lab admin, public DNS


@pytest.fixture(autouse=True)
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    database.get_db()["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    yield
    database._client = old


def lookup(ip):
    return client.get("/assets/lookup", params={"ip": ip})


def test_lab_addresses_in_the_allowlist_belong_to_an_asset():
    lab = [e["ip"] for e in load_allowlist() if e["ip"] not in NOT_ASSETS]
    assert lab, "the allowlist should contain lab addresses"
    for ip in lab:
        assert lookup(ip).status_code == 200, f"{ip} is allowlisted but is not an asset"


def test_allowlist_entries_map_to_the_expected_assets():
    expected = {"172.18.0.1": "Docker Network Gateway", "172.18.0.5": "HAProxy", "172.18.0.99": "Pentest Runner"}
    for ip, name in expected.items():
        assert lookup(ip).json()["name"] == name


def test_attackers_are_never_assets():
    for inc in load_incidents():
        # note: the documentation ranges (203.0.113.x ...) count as "private" in Python, so compare with the lab subnet
        if ipaddress.ip_address(inc["src_ip"]) not in LAB_NET:
            assert lookup(inc["src_ip"]).status_code == 404, inc["incident_id"]


def test_every_internal_source_in_the_fixtures_is_a_known_asset():
    for inc in load_incidents():
        if ipaddress.ip_address(inc["src_ip"]) in LAB_NET:
            assert lookup(inc["src_ip"]).status_code == 200, (inc["incident_id"], inc["src_ip"])


def test_traffic_aimed_at_the_website_resolves_to_the_website_or_the_proxy():
    destinations = {e["dst_ip"] for s in list_scenarios() for e in load_events(s) if e["dst_ip"]}
    assert destinations <= {"172.18.0.10", "172.18.0.5"}
    names = {lookup(ip).json()["name"] for ip in destinations}
    assert names == {"skyline-web", "HAProxy"}


def test_the_pentest_runner_address_is_the_one_the_pentest_fixture_uses():
    sources = {e["src_ip"] for e in load_events("authorized_pentest")}
    assert sources == {"172.18.0.99"}
    assert lookup("172.18.0.99").json()["name"] == "Pentest Runner"
