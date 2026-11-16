"""W4: the automatic job.

The plan asks for a "job that recalculates likelihood from incidents and open findings", so that a new attack
or finding changes the matching risk score WITHOUT anybody pressing a button. This module runs
recalculate_all() on a timer inside the API process.

  RECALC_INTERVAL_SECONDS   how often (default 300). 0 switches the job off.
  RECALC_WINDOW_DAYS        how far back incidents count (default 30).

GET /risks/recalculate/status shows whether it is running and what the last run did.
A failed run (for example the database is down) is recorded and the loop carries on with the next one.
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from .risk_live import DEFAULT_DAYS, recalculate_all

log = logging.getLogger("grc.scheduler")


class RecalcJob:
    def __init__(self) -> None:
        self.interval = 0
        self.days = DEFAULT_DAYS
        self.runs = 0
        self.failures = 0
        self.last_run: str | None = None
        self.last_result: dict | None = None
        self.last_error: str | None = None
        self._task: asyncio.Task | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def run_once(self) -> dict | None:
        """One recalculation. Never raises: the outcome is stored in the status fields."""
        self.last_run = datetime.now(timezone.utc).isoformat()
        try:
            self.last_result = recalculate_all(self.days)
            self.last_error = None
            self.runs += 1
            return self.last_result
        except Exception as exc:   # the database can be down for a moment; try again next time
            self.failures += 1
            self.last_error = f"{type(exc).__name__}: {exc}"[:300]
            log.warning("risk recalculation failed: %s", self.last_error)
            return None

    async def _loop(self) -> None:
        while True:
            await asyncio.to_thread(self.run_once)
            await asyncio.sleep(self.interval)

    def start(self, interval: float, days: int = DEFAULT_DAYS) -> None:
        if interval <= 0 or self.running:
            return
        self.interval, self.days = interval, days
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def status(self) -> dict:
        return {"enabled": self.running, "interval_seconds": self.interval, "window_days": self.days,
                "runs": self.runs, "failures": self.failures, "last_run": self.last_run,
                "last_result": self.last_result, "last_error": self.last_error}


job = RecalcJob()


def _env_number(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


@asynccontextmanager
async def lifespan(_app):
    job.start(_env_number("RECALC_INTERVAL_SECONDS", 300), int(_env_number("RECALC_WINDOW_DAYS", DEFAULT_DAYS)))
    try:
        yield
    finally:
        await job.stop()
