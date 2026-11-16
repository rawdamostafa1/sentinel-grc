"""تيست بسيط بيشتغل من غير MongoDB حقيقي: pytest"""
import mongomock
from fastapi.testclient import TestClient
import app.database as database

database._client = mongomock.MongoClient()

from app.main import app  # noqa: E402
import seed  # noqa: E402
from app.seed_data import SEED_ASSETS  # noqa: E402

client = TestClient(app)


def test_seed_and_lookup():
    seed.run()
    assert len(client.get("/assets").json()) == len(SEED_ASSETS)
    r = client.get("/assets/lookup", params={"name": "haproxy"})
    assert r.status_code == 200 and r.json()["criticality"] == 5


def test_lookup_by_ip():
    client.put("/assets/AST-001", json={"ip_addresses": ["172.20.0.5"]})
    r = client.get("/assets/lookup", params={"ip": "172.20.0.5"})
    assert r.json()["name"] == "skyline-web"
    assert client.get("/assets/lookup", params={"ip": "9.9.9.9"}).status_code == 404


def test_validation():
    bad = dict(name="x", type="application", owner="a", business_service="b",
               criticality=9, data_classification="internal", exposure="internal")
    assert client.post("/assets", json=bad).status_code == 422


def test_seed_data_is_consistent():
    ids = [a["asset_id"] for a in SEED_ASSETS]
    names = [a["name"] for a in SEED_ASSETS]
    hostnames = [h for a in SEED_ASSETS for h in a.get("hostnames", [])]
    ips = [ip for a in SEED_ASSETS for ip in a.get("ip_addresses", [])]
    assert len(set(ids)) == len(ids) and len(set(names)) == len(names)
    assert len(set(hostnames)) == len(hostnames)   # a hostname must point to one asset only
    assert len(set(ips)) == len(ips)


def test_every_platform_service_can_be_found_by_its_compose_name():
    seed.run()
    for name in ("haproxy", "redis", "mongo", "sniffer", "log-shipper", "detector", "correlator",
                 "enrichment", "pentest-runner", "api", "reporter"):
        assert client.get("/assets/lookup", params={"name": name}).status_code == 200, name


def test_running_the_seed_again_keeps_addresses_edited_by_hand():
    seed.run()
    client.put("/assets/AST-004", json={"ip_addresses": ["172.20.0.20"], "hostnames": ["mysql", "db"]})
    seed.run()
    asset = client.get("/assets/AST-004").json()
    assert asset["ip_addresses"] == ["172.20.0.20"] and asset["hostnames"] == ["mysql", "db"]
    assert client.get("/assets/lookup", params={"ip": "172.20.0.20"}).json()["asset_id"] == "AST-004"


# ---------- IPs and the second batch of assets ----------
import ipaddress  # noqa: E402

LAB_NET = ipaddress.ip_network("172.18.0.0/16")


def test_there_are_30_assets_and_the_new_ones_exist():
    seed.run()
    assert len(SEED_ASSETS) >= 30
    for name in ("Booking & Payment Flow", "Check-in Service", "Policy Guard & Playbooks", "ML Model Artifacts",
                 "Audit Log", "VirusTotal API", "AbuseIPDB API", "LLM Provider", "Telegram Bot API",
                 "Docker Network Gateway"):
        assert client.get("/assets/lookup", params={"name": name}).status_code == 200, name


def test_every_seeded_ip_is_a_valid_lab_address():
    for asset in SEED_ASSETS:
        for ip in asset.get("ip_addresses", []):
            assert ipaddress.ip_address(ip) in LAB_NET, (asset["asset_id"], ip)


def test_every_seeded_ip_finds_its_own_asset():
    seed.run()
    for asset in SEED_ASSETS:
        for ip in asset.get("ip_addresses", []):
            # hand-edited addresses from other tests may have replaced one, so compare with the database
            stored = client.get(f"/assets/{asset['asset_id']}").json()["ip_addresses"]
            if ip in stored:
                found = client.get("/assets/lookup", params={"ip": ip}).json()
                assert found["asset_id"] == asset["asset_id"], ip


def test_addresses_agreed_with_the_other_teams():
    by_name = {a["name"]: a for a in SEED_ASSETS}
    assert by_name["skyline-web"]["ip_addresses"] == ["172.18.0.10"]          # Mohamed Osama's scope list
    assert by_name["Docker Network Gateway"]["ip_addresses"] == ["172.18.0.1"]  # Mohamed Osama's allowlist
    assert by_name["HAProxy"]["ip_addresses"] == ["172.18.0.5"]                # fixtures allowlist
    assert by_name["Pentest Runner"]["ip_addresses"] == ["172.18.0.99"]        # fixtures allowlist


def test_external_services_and_website_parts_have_no_address_of_their_own():
    for asset in SEED_ASSETS:
        if asset["type"] == "third-party":
            assert asset["exposure"] == "external" and not asset.get("ip_addresses"), asset["name"]
    for name in ("Admin Panel", "Auth & Sessions", "Booking & Payment Flow", "Check-in Service"):
        assert not next(a for a in SEED_ASSETS if a["name"] == name).get("ip_addresses")


def test_the_money_and_data_assets_are_rated_high():
    by_name = {a["name"]: a for a in SEED_ASSETS}
    for name in ("skyline-web", "Booking & Payment Flow", "MySQL (skyline)", "HAProxy", "Policy Guard & Playbooks"):
        assert by_name[name]["criticality"] == 5, name
    assert all(a["data_classification"] == "confidential" for a in SEED_ASSETS if a["name"] in
               ("Booking & Payment Flow", "MySQL (skyline)", "Audit Log"))


def test_seed_fills_missing_addresses_on_existing_assets_but_never_overwrites_hand_edits():
    database._client = mongomock.MongoClient()          # a database created BEFORE the addresses existed
    old = [{k: v for k, v in a.items() if k != "ip_addresses"} for a in SEED_ASSETS[:3]]
    for a in old:
        client.post("/assets", json={**a, "hostnames": a.get("hostnames", [])})
    client.put("/assets/AST-002", json={"ip_addresses": ["172.18.0.200"]})       # edited by hand
    seed.run()
    assert client.get("/assets/AST-001").json()["ip_addresses"] == ["172.18.0.10"]   # filled in
    assert client.get("/assets/AST-002").json()["ip_addresses"] == ["172.18.0.200"]  # kept
    assert client.get("/assets/lookup", params={"ip": "172.18.0.10"}).json()["name"] == "skyline-web"
    assert len(client.get("/assets").json()) == len(SEED_ASSETS)                    # the new assets arrive too
