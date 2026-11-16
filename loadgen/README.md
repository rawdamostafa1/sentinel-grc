# Synthetic data and load generator (W9)

Writes realistic events into the Redis `events` stream at a rate you choose, and measures what comes out the other
side. **This is a stress test (capacity), not a detection-accuracy test.** Never mix the two numbers in the report.

## Quick start
```
pip install -r requirements.txt
python -m loadgen.stress --fake --count 10000                  # self-test of the tooling, no Redis needed
python -m loadgen.stress --redis-url redis://localhost:6379 --count 10000 --rate 1000 --consumers 2
python -m loadgen.stress --redis-url redis://localhost:6379 --count 50000 --rate 2000 --no-consumer
```
The last form only generates: let Alaa's detector read the stream and look at his metrics.
`--fake` uses an in-memory Redis, so its numbers prove the tools work, they say nothing about the real pipeline.

## What the traffic looks like
- 19-field Event schema, identical to `fixtures/events/*.json` (a test checks this).
- Attacks as short sessions: `brute_force`, `credential_stuffing`, `sql_injection`, `dos_flood`, `scan`, `upload`.
- Normal traffic: browsing, logins (with the odd typo), network flows, and a **legitimate heavy user** (must not be blocked).
- `--attack-ratio` (default 0.25) sets the share of attack traffic. `--seed` repeats a run exactly.
- Varied source addresses (documentation ranges and shared address space only, never real hosts), ports, times (spread
  over an hour) and statuses. Attackers come back from a small pool, so repeat offenders appear.

## Stream message format
`XADD events * event_id <id> sent_at_ms <epoch ms> data <event as JSON>`. Agree the final format with Alaa (A1/A2) and
change it in one place: `loadgen/sinks.py: encode()`. `--maxlen` caps the stream.

## What is measured
Events sent and the real send rate, events processed and the process rate, **lost**, **duplicates**, **dead letters**
(unparseable messages go to `events:dead`), messages left **pending** (read but never acknowledged), and the end-to-end
latency (sent to read) as p50 / p95 / p99 / max. Every run saves `loadgen/results/stress-<time>.json` and `.md`.

## Report honestly
State the machine, Redis version, rate, count and consumers next to every number. A latency measured with `--fake`
or at 100 events per second says nothing about 10,000 events per second.
