# What changed compared with sentinel-grc-main_1.zip (you can delete this file after reading it)

## Changed files (14)
| File | What changed |
|---|---|
| app/seed_data.py | 30 assets (AST-021..030 are new) and lab IP addresses; the header says which IPs are real and which are placeholders |
| seed.py | also FILLS empty hostnames/ip_addresses on assets that already exist (never overwrites hand edits) |
| seed_controls.py | FEATURE_ASSETS points at the new, more precise assets |
| seed_incidents.py | no longer wipes ALL incidents: only touches fixture incidents (source="fixture"), has --remove |
| app/main.py | scheduler (lifespan), GET /risks/recalculate/status, portal router |
| app/kri_calc.py, app/kris.py | the "ATT&CK coverage" KRI now has a value (from the alerts that fired) |
| fixtures/incidents.json | + handled_autonomously (for the autonomy KRI) |
| fixtures/loader.py, fixtures/README.md | loaders and notes for the new fixtures |
| test_assets.py | + 7 tests (IPs, new assets, seed fills empty addresses) |
| requirements.txt | + redis, fakeredis (for the load generator tests) |
| .env.example, .gitignore | new settings, ignore loadgen/results |

## New files (39)
- W4 job: app/scheduler.py, test_scheduler.py
- W9: loadgen/ (events, sinks, consume, metrics, stress, README), test_loadgen.py
- W10: fixtures/decisions.json, actions.json, findings.json, policies.json, policy_exceptions.json, compliance_snapshot.json
- Seeders: seed_all.py, seed_demo.py, seed_findings.py; check_db.py (what is in the database)
- Client portal backend: app/portal.py, app/portal_scoring.py, test_portal.py
- For other teams: grc_client/, docs/contracts/asset_lookup.md, docs/api.md
- Packaging: README.md, Dockerfile, requirements-runtime.txt, .dockerignore, docker-compose.grc.yml, .github/workflows/tests.yml
- Tests: test_asset_ips.py, test_seed_controls.py, test_findings.py, test_demo_fixtures.py, test_grc_client.py, test_check_db.py

159 tests, all pass: python -m pytest
