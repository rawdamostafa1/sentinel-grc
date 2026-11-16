"""Tests for grc_client (the way other teams ask for assets) and the asset lookup contract."""
import mongomock
import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app
from app.seed_data import SEED_ASSETS
from grc_client import GrcClient, GrcUnavailable

api = TestClient(app)


@pytest.fixture(autouse=True)
def fake_db():
    old = database._client
    database._client = mongomock.MongoClient()
    database.get_db()["assets"].insert_many([dict(a) for a in SEED_ASSETS])
    yield
    database._client = old


def through_the_api(path, params):
    response = api.get(path, params=params)
    return response.status_code, (response.json() if response.status_code == 200 else None)


def client(**kw):
    return GrcClient(base_url="http://grc:8001", fetch=through_the_api, **kw)


def test_lookup_by_ip_and_by_name():
    grc = client()
    assert grc.lookup_asset(ip="172.18.0.10")["name"] == "skyline-web"
    assert grc.lookup_asset(name="haproxy")["asset_id"] == "AST-005"


def test_an_attacker_address_is_none_not_an_error():
    assert client().lookup_asset(ip="203.0.113.7") is None


def test_criticality_score_is_ready_for_the_severity_formula():
    grc = client()
    assert grc.criticality_score(ip="172.18.0.10") == 1.0
    assert grc.criticality_score(name="Admin Panel") == 0.8
    assert grc.criticality_score(ip="203.0.113.7", unknown=0.6) == 0.6


def test_is_asset():
    grc = client()
    assert grc.is_asset("172.18.0.1") and not grc.is_asset("8.8.8.8")


def test_answers_are_cached():
    calls = []

    def counting(path, params):
        calls.append(params)
        return through_the_api(path, params)
    grc = GrcClient(fetch=counting, cache_ttl=60)
    for _ in range(5):
        grc.lookup_asset(ip="172.18.0.10")
        grc.lookup_asset(ip="203.0.113.7")                # a 404 is cached too
    assert len(calls) == 2
    GrcClient(fetch=counting, cache_ttl=0).lookup_asset(ip="172.18.0.10")
    assert len(calls) == 3


def test_a_service_that_is_down_raises_or_returns_the_default():
    def down(path, params):
        raise GrcUnavailable("connection refused")
    grc = GrcClient(fetch=down)
    with pytest.raises(GrcUnavailable):
        grc.lookup_asset(ip="172.18.0.10")
    assert grc.lookup_asset(ip="172.18.0.10", default=None) is None
    assert grc.is_asset("172.18.0.10") is False and grc.is_asset("172.18.0.10", default=True) is True
    assert grc.criticality_score(ip="172.18.0.10", unknown=0.6) == 0.6


def test_an_unexpected_status_is_not_cached_as_an_answer():
    grc = GrcClient(fetch=lambda path, params: (500, None))
    with pytest.raises(GrcUnavailable):
        grc.lookup_asset(ip="172.18.0.10")
    assert grc.lookup_asset(ip="172.18.0.10", default="x") == "x"


def test_nothing_to_look_up_is_a_mistake():
    with pytest.raises(ValueError):
        client().lookup_asset()


def test_the_real_http_path_handles_a_server_that_is_not_there():
    grc = GrcClient(base_url="http://127.0.0.1:9", timeout=0.5)            # nothing listens on port 9
    with pytest.raises(GrcUnavailable):
        grc.lookup_asset(ip="172.18.0.10")


def test_contract_answers_of_the_api():
    assert api.get("/assets/lookup").status_code == 400
    assert api.get("/assets/lookup", params={"ip": "203.0.113.7"}).status_code == 404
    body = api.get("/assets/lookup", params={"ip": "172.18.0.10"}).json()
    assert {"asset_id", "name", "criticality", "hostnames", "ip_addresses", "exposure", "data_classification"} <= set(body)
