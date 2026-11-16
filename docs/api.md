# GRC service API (port 8001)

Interactive docs: `http://localhost:8001/docs`

| Area | Endpoints | Task |
|---|---|---|
| Assets | `POST/GET /assets`, `GET/PUT/DELETE /assets/{id}`, `GET /assets/lookup`, `POST /assets/{id}/seen` | W1 |
| Relations | `GET /assets/{id}/summary`, `/incidents`, `/findings`, `/risks`, `/controls` | W2 |
| Risk register | `POST/GET /risks`, `GET/PUT/DELETE /risks/{id}`, `POST /risks/{id}/accept` | W3 |
| Live risk | `POST /risks/recalculate`, `GET /risks/recalculate/status`, `GET /risks/{id}/history` | W4 |
| Heatmap | `GET /risks/heatmap?basis=inherent|residual` | W7 backend |
| KRIs | `GET /kris` | W5 |
| Client portal | `GET /portal/summary?days=30` | W8 backend |
| Health | `GET /health` | |

Collections it reads that belong to other owners: `incidents` and `alerts` (Alaa), `findings` (Omar),
`actions` (Mohamed Osama), `decisions` (Habiba), `policies`, `policy_exceptions`, `compliance_snapshots`, `reports` (Amira).
When one is empty the answer says so (`no_data`, empty list) and never invents numbers.

The service has no login yet. Do not expose port 8001 outside the Docker network.
