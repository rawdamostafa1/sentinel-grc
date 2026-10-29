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
