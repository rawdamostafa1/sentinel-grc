# Sentinel GRC service (Rawda: GRC part one)

Assets, risks, live risk, KRIs and the data for the Client Portal. A FastAPI service on port 8001 with MongoDB.

| Task | What | Where |
|---|---|---|
| W1 | Asset inventory and `GET /assets/lookup` | `app/main.py`, `app/models.py`, `app/seed_data.py` |
| W2 | Assets linked to incidents, findings, risks, controls | `app/relations.py`, `seed_controls.py` |
| W3 | Risk register, scoring, acceptance with expiry | `app/risks.py`, `app/risk_scoring.py` |
| W4 | Live risk calculation, **automatic job**, history | `app/risk_live*.py`, `app/scheduler.py` |
| W5 | Key Risk Indicators (`GET /kris`) | `app/kris.py`, `app/kri_calc.py` |
| W9 | Synthetic data and load generator | `loadgen/` |
| W10 | Test fixtures | `fixtures/` |
| W6, W7, W8 | Dashboard pages | in the dashboard project (backend parts: `app/heatmap.py`, `app/portal.py`) |

## Run
```
python -m venv venv
venv\Scripts\activate                  (Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env                 (then put your MONGO_URL in .env; it is never committed)
python seed_all.py                     assets, controls, risks   (add --demo for demo incidents, findings, policies ...)
uvicorn app.main:app --port 8001
python check_db.py                     what is in the database, and what looks wrong
python -m pytest                       all tests (fake database, no MongoDB needed)
```
API docs at `http://localhost:8001/docs`, list of endpoints in `docs/api.md`.

## Settings (`.env`)
`MONGO_URL`, `MONGO_DB`, `RECALC_INTERVAL_SECONDS` (default 300, 0 = off), `RECALC_WINDOW_DAYS` (default 30).

## For the other teams
- `docs/contracts/asset_lookup.md` and `grc_client/`: ask which asset an address belongs to and how critical it is.
- `fixtures/`: sample events, alerts, incidents, evidence, decisions, actions, findings, policies. Develop against them.
- `loadgen/`: stress test the pipeline (see `loadgen/README.md`).

## Data that belongs to other owners
Read, never invented: `incidents` and `alerts` (Alaa), `findings` (Omar), `actions` (Mohamed Osama), `decisions` (Habiba),
`policies`, `policy_exceptions`, `compliance_snapshots`, `reports` (Amira). Until they exist, the KRIs say `no_data`.
`python seed_all.py --demo` fills them with clearly marked demo documents (`source: "fixture"`) and
`python seed_all.py --remove-demo` removes only those.

## Team decisions to review (all in one place each)
- Risk likelihood and impact weights: `app/risk_live_scoring.py`.
- Client posture score `100 * (1 - average residual risk / 25)`: `app/portal_scoring.py`.
- ATT&CK techniques counted by the coverage KRI: `app/kri_calc.py` (replace with Ariam's coverage analysis).
- Asset criticality, owners and the placeholder lab IPs: `app/seed_data.py` (header explains which IPs are real).

## Docker
`docker compose -f docker-compose.grc.yml up --build` runs the service with its own MongoDB.
The service has **no login yet**: keep port 8001 inside the Docker network.
