"""No third-party packages needed (standard library only), so any service can copy this folder.

Rules of the contract (docs/contracts/asset_lookup.md):
  * HTTP 404 is a normal answer: "this address / name is not a Skyline asset". It returns None.
  * Any other failure (service down, timeout) raises GrcUnavailable, or returns `default` when one is given.
    The caller decides what an unknown asset means; the severity formula should use a neutral value.
  * Answers are cached for `cache_ttl` seconds, so a flood of events does not become a flood of requests.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

MISSING = object()


class GrcUnavailable(RuntimeError):
    pass


class GrcClient:
    def __init__(self, base_url: str | None = None, timeout: float = 2.0, cache_ttl: float = 60.0, fetch=None):
        self.base_url = (base_url or os.getenv("GRC_URL", "http://grc:8001")).rstrip("/")
        self.timeout, self.cache_ttl = timeout, cache_ttl
        self._fetch = fetch or self._http_get      # tests can pass a function(path, params) -> (status, json)
        self._cache: dict[tuple, tuple[float, dict | None]] = {}

    def _http_get(self, path: str, params: dict):
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:       # noqa: S310 (fixed http(s) base url)
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise GrcUnavailable(f"GRC service not reachable: {exc}") from exc

    def lookup_asset(self, ip: str | None = None, name: str | None = None, default=MISSING) -> dict | None:
        """Find an asset by IP address or by name/hostname. None = not a Skyline asset."""
        if not ip and not name:
            raise ValueError("send ip or name")
        key = ("ip", ip) if ip else ("name", name)
        cached = self._cache.get(key)
        if cached and time.monotonic() - cached[0] < self.cache_ttl:
            return cached[1]
        try:
            status, body = self._fetch("/assets/lookup", {"ip": ip} if ip else {"name": name})
        except GrcUnavailable:
            if default is MISSING:
                raise
            return default
        if status == 404:
            asset = None
        elif status == 200:
            asset = body
        else:
            if default is MISSING:
                raise GrcUnavailable(f"unexpected answer {status} from the GRC service")
            return default
        self._cache[key] = (time.monotonic(), asset)
        return asset

    def is_asset(self, ip: str, default: bool = False) -> bool:
        """True when the address belongs to a Skyline asset. `default` is returned when the service is down."""
        try:
            return self.lookup_asset(ip=ip) is not None
        except GrcUnavailable:
            return default

    def criticality_score(self, ip: str | None = None, name: str | None = None, unknown: float | None = None) -> float | None:
        """criticality 1-5 as 0.2-1.0, the `asset_criticality` input of the severity formula (Project Details 6.3).
        Returns `unknown` when the address is not an asset or the service is down."""
        asset = self.lookup_asset(ip=ip, name=name, default=None)
        return asset["criticality"] / 5 if asset else unknown
