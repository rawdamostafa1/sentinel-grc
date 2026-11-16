"""Small client for the GRC service, for the other teams (severity engine, agent, detector).

    from grc_client import GrcClient
    grc = GrcClient()                          # GRC_URL, default http://grc:8001
    asset = grc.lookup_asset(ip="172.18.0.10")   # dict, or None when it is not a Skyline asset
    grc.criticality_score(ip="172.18.0.10")      # 1.0  (criticality / 5, ready for the severity formula)
"""
from .client import GrcClient, GrcUnavailable

__all__ = ["GrcClient", "GrcUnavailable"]
