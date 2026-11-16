"""Realistic synthetic events in the unified Event schema (the same 19 fields as fixtures/events/*.json).

Everything is driven by one seed, so a run can be repeated exactly. Addresses come from ranges that are
reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and shared address space
(100.64.0.0/10), so nothing here can point at a real host. The lab subnet 172.18.0.0/16 is the target side.

Attack types (each one a short "session" of related events, like the real traffic would be):
  brute_force, credential_stuffing, sql_injection, dos_flood, scan, upload
Normal traffic: browsing, normal logins (with the odd typo), and a legitimate heavy user (must NOT be blocked).
Network flows (source "network") are mixed in with a few cicflowmeter-style features.
"""
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SKYLINE_WEB = "172.18.0.10"
HAPROXY = "172.18.0.5"
DOC_RANGES = ("192.0.2", "198.51.100", "203.0.113")
BROWSER_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile/15E148",
)
BOT_UAS = ("python-requests/2.31", "curl/8.5.0", "sqlmap/1.8", "Nikto/2.5.0", "Hydra", "Go-http-client/2.0")
PAGES = ("/", "/flights", "/flights?from=CAI&to=DXB", "/flights?from=CAI&to=LHR", "/booking", "/account", "/checkin",
         "/static/app.js", "/static/style.css", "/about", "/contact")
SQLI = ("/flights?from=CAI' OR '1'='1", "/flights?from=CAI' UNION SELECT email,passwordHash FROM User--",
        "/flights?from=CAI';--", "/flights?from=1; DROP TABLE Booking--")
SCAN_PATHS = ("/admin.php", "/backup.zip", "/.git/config", "/phpmyadmin/", "/.env", "/wp-login.php", "/server-status",
              "/test/", "/old/", "/config.bak", "/admin/users", "/api/v1/debug")
ATTACKS = ("brute_force", "credential_stuffing", "sql_injection", "dos_flood", "scan", "upload")
NORMAL = ("browsing", "login", "heavy_user", "flow")
EVENT_FIELDS = ("event_id", "ts", "source", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "user",
                "session_id", "http_method", "url", "status", "user_agent", "event_type", "features", "raw",
                "tags", "tenant_id")


@dataclass
class LoadConfig:
    count: int = 10_000
    seed: int = 42
    attack_ratio: float = 0.25          # share of events that belong to an attack session
    start: datetime | None = None       # first event time (default: now)
    span_minutes: float = 60.0          # the generated traffic is spread over this window
    tenant_id: str = "skyline"


def _ts(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class EventFactory:
    def __init__(self, config: LoadConfig):
        self.config = config
        self.rng = random.Random(config.seed)
        self.start = config.start or datetime.now(timezone.utc)
        self.n = 0
        self.attackers = [self._doc_ip() for _ in range(60)]        # a pool, so some attackers come back (repeat offenders)

    # ---- addresses and ids ----
    def _doc_ip(self) -> str:
        return f"{self.rng.choice(DOC_RANGES)}.{self.rng.randint(1, 254)}"

    def _user_ip(self) -> str:
        return f"100.{self.rng.randint(64, 127)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"

    def _event(self, moment: datetime, **fields) -> dict:
        self.n += 1
        rng = self.rng
        event = dict.fromkeys(EVENT_FIELDS)
        event.update(event_id=f"LG-{self.config.seed}-{self.n:08d}", ts=_ts(moment), source="haproxy",
                     dst_ip=HAPROXY, src_port=rng.randint(1024, 65535), dst_port=80, protocol="tcp",
                     event_type="http_request", features={}, tags=[], tenant_id=self.config.tenant_id)
        event.update(fields)
        if event["source"] != "network":
            event["raw"] = f'{event["src_ip"]} "{event["http_method"]} {event["url"]}" {event["status"]} "{event["user_agent"]}"'
        else:
            event["raw"] = "cicflowmeter flow"
        return event

    def _http(self, moment, ip, method, url, status, ua, **extra) -> dict:
        return self._event(moment, src_ip=ip, http_method=method, url=url, status=status, user_agent=ua, **extra)

    # ---- one session per scenario: returns a list of events ----
    def session(self, kind: str, at: datetime) -> list[dict]:
        return getattr(self, f"_s_{kind}")(at)

    def _s_browsing(self, at):
        ip, ua, sid = self._user_ip(), self.rng.choice(BROWSER_UAS), f"S{self.rng.randint(10**6, 10**7)}"
        return [self._http(at + timedelta(seconds=i * self.rng.uniform(1, 9)), ip, "GET", self.rng.choice(PAGES),
                           self.rng.choices((200, 304, 404), (90, 8, 2))[0], ua, session_id=sid)
                for i in range(self.rng.randint(2, 7))]

    def _s_login(self, at):
        ip, ua, user = self._user_ip(), self.rng.choice(BROWSER_UAS), f"user{self.rng.randint(1, 4000)}@skyline.air"
        events = []
        if self.rng.random() < 0.15:                                   # a typo before the right password
            events.append(self._http(at, ip, "POST", "/auth/login", 401, ua, event_type="login_failed", user=user))
            at += timedelta(seconds=self.rng.uniform(3, 15))
        events.append(self._http(at, ip, "POST", "/auth/login", 302, ua, event_type="login_ok", user=user))
        return events

    def _s_heavy_user(self, at):                                       # looks busy but is a real customer: all 200
        ip, ua, user = self._user_ip(), self.rng.choice(BROWSER_UAS), f"traveler{self.rng.randint(1, 50)}@skyline.air"
        return [self._http(at + timedelta(seconds=i * self.rng.uniform(1, 3)), ip, "GET",
                           f"/flights?from=CAI&to={self.rng.choice(('DXB', 'LHR', 'JFK', 'CDG', 'FRA'))}", 200, ua,
                           user=user, event_type="login_ok" if i == 0 else "http_request") for i in range(self.rng.randint(8, 14))]

    def _s_flow(self, at):
        ip = self._user_ip()
        feats = {"Flow Duration": self.rng.randint(1_000, 5_000_000), "Total Fwd Packets": self.rng.randint(2, 60),
                 "Flow Packets/s": round(self.rng.uniform(1, 80), 2), "SYN Flag Count": self.rng.randint(0, 2)}
        return [self._event(at, source="network", dst_ip=SKYLINE_WEB, src_ip=ip, event_type="flow", features=feats)]

    def _s_brute_force(self, at):
        ip, ua = self.rng.choice(self.attackers), self.rng.choice(BOT_UAS)
        user = f"admin{self.rng.randint(1, 5)}@skyline.air"
        events, moment = [], at
        for _ in range(self.rng.randint(6, 30)):
            events.append(self._http(moment, ip, "POST", "/auth/login", 401, ua, event_type="login_failed", user=user))
            moment += timedelta(seconds=self.rng.uniform(0.5, 4))
        if self.rng.random() < 0.2:                                    # sometimes the guessing works
            events.append(self._http(moment, ip, "POST", "/auth/login", 302, ua, event_type="login_ok", user=user,
                                     tags=["success_after_failures"]))
        return events

    def _s_credential_stuffing(self, at):
        ip, ua = self.rng.choice(self.attackers), self.rng.choice(BOT_UAS)
        return [self._http(at + timedelta(seconds=i * self.rng.uniform(0.2, 1.5)), ip, "POST", "/auth/login", 401, ua,
                           event_type="login_failed", user=f"user{self.rng.randint(1, 4000)}@skyline.air")
                for i in range(self.rng.randint(15, 40))]

    def _s_sql_injection(self, at):
        ip, ua = self.rng.choice(self.attackers), self.rng.choice(("sqlmap/1.8",) + BOT_UAS)
        return [self._http(at + timedelta(seconds=i * self.rng.uniform(0.5, 3)), ip, "GET", self.rng.choice(SQLI),
                           self.rng.choice((200, 500, 500)), ua) for i in range(self.rng.randint(2, 8))]

    def _s_dos_flood(self, at):
        ip, ua = self.rng.choice(self.attackers), self.rng.choice(BROWSER_UAS + BOT_UAS)
        n = self.rng.randint(40, 120)
        events = [self._http(at + timedelta(milliseconds=i * self.rng.randint(5, 60)), ip, "GET", "/flights",
                             429 if i > 8 else 200, ua, tags=["rate_sample"]) for i in range(n)]
        events.append(self._event(at, source="network", dst_ip=SKYLINE_WEB, src_ip=ip, event_type="flow",
                                  features={"Flow Duration": 1200, "Total Fwd Packets": n * 40, "Flow Packets/s": 4000.0,
                                            "SYN Flag Count": n * 40}))
        return events

    def _s_scan(self, at):
        ip, ua = self.rng.choice(self.attackers), self.rng.choice(("Nikto/2.5.0",) + BOT_UAS)
        return [self._http(at + timedelta(seconds=i * self.rng.uniform(0.1, 1.2)), ip, "GET", self.rng.choice(SCAN_PATHS), 404, ua)
                for i in range(self.rng.randint(10, 35))]

    def _s_upload(self, at):
        ip, ua = self.rng.choice(self.attackers), self.rng.choice(BOT_UAS)
        name = self.rng.choice(("shell.php", "cmd.jsp", "x.exe", "payload.php5"))
        return [self._http(at + timedelta(seconds=i * 2), ip, "POST", f"/account/upload?file={name}",
                           self.rng.choice((200, 201, 403)), ua, tags=["upload"]) for i in range(self.rng.randint(1, 3))]

    # ---- the stream of events ----
    def chunks(self, size: int = 2_000):
        """Yield lists of events in time order. Each chunk covers the next slice of the time window."""
        cfg, rng = self.config, self.rng
        total_chunks = max(1, -(-cfg.count // size))
        window = timedelta(minutes=cfg.span_minutes) / total_chunks
        produced = 0
        for index in range(total_chunks):
            begin = self.start + window * index
            want = min(size, cfg.count - produced)
            batch: list[dict] = []
            while len(batch) < want:
                kind = (rng.choice(ATTACKS) if rng.random() < cfg.attack_ratio
                        else rng.choices(NORMAL, (55, 20, 5, 20))[0])
                batch.extend(self.session(kind, begin + window * rng.random() * 0.9))
            batch.sort(key=lambda e: e["ts"])
            batch = batch[:want]
            produced += len(batch)
            yield batch

    def events(self):
        for chunk in self.chunks():
            yield from chunk
