# Contract: Asset lookup (producer: Rawda, consumers: severity engine, AI agent, risk job)

Section 10 of the Task Plan: "Lookup by IP or name, criticality scale".

## Request
`GET /assets/lookup?ip=172.18.0.10` or `GET /assets/lookup?name=haproxy`

- `ip`: an address of the asset (`ip_addresses`).
- `name`: the asset name or one of its `hostnames` (the Docker Compose service name).
- Send one of them. If you send both, `ip` wins. Neither gives `400`.

## Answers
| Status | Meaning |
|---|---|
| `200` | A Skyline asset. Body below. |
| `404` | **Not a Skyline asset.** This is normal: every attacker address is a 404. It is not an error. |
| `400` | Neither `ip` nor `name` was sent. |

```json
{
  "asset_id": "AST-001", "name": "skyline-web", "type": "application", "owner": "Web Team",
  "business_service": "Flight booking", "criticality": 5,
  "data_classification": "confidential", "exposure": "internet-facing", "environment": "lab",
  "hostnames": ["skyline-web"], "ip_addresses": ["172.18.0.10"], "description": "...",
  "status": "active", "last_seen": null
}
```

## Criticality scale (1 to 5)
| | Meaning |
|---|---|
| 5 | The business stops or customer/payment data leaks if it is lost (website, database, proxy, booking and payment flow, Policy Guard) |
| 4 | Important, with a workaround (admin panel, login, agent, executor, detector) |
| 3 | Useful, an outage hurts but does not stop the service |
| 2 | Convenience (reporter, external reputation APIs, notification bot, lab gateway) |
| 1 | Nobody would notice |

For the severity formula use `criticality / 5` (`0.2` to `1.0`). For an unknown address use a neutral value
agreed with Alaa; do not use `0`.

## How an IP maps to an asset
An address identifies the **host**. The parts of the website (Admin Panel, Auth & Sessions, Booking and Check-in) have
no address of their own, so an IP lookup returns `skyline-web`; a name lookup returns the part. Third-party services
(VirusTotal, AbuseIPDB, LLM provider, Telegram, Duffel) have no address in our network.

## Using it from Python
Copy `grc_client/` (standard library only):

```python
from grc_client import GrcClient
grc = GrcClient()                                   # reads GRC_URL, default http://grc:8001
asset = grc.lookup_asset(ip="172.18.0.10", default=None)   # None when unknown or when the service is down
score = grc.criticality_score(ip=event["dst_ip"], unknown=0.6)
```
Answers are cached for 60 seconds. Develop against the fixtures first (`fixtures/`): "mock first" in the Task Plan.

## Changing this contract
Only through a pull request that Alaa, Habiba and Mohamed Osama approve (Task Plan, working agreements).
