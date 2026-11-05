#!/usr/bin/env python3
# =============================================================================
# Polaris Cloud Console  --  Directory Traversal Lab (Security+ SY0-701)
#
# A deliberately vulnerable teaching app. Students register, sign in, explore a
# fake cloud dashboard and the "Nightwatch" SOC, then abuse the /show-report
# endpoint:
#
#       /show-report?report=nov05.log          <- intended use
#       /show-report?report=../../../private_folder/flag.txt   <- the attack
#
# The report viewer joins user input onto the reports directory and opens it
# WITH NO SANITIZATION, so "../" climbs out of the reports folder and reads any
# file the process can see -- including the flag at /private_folder/flag.txt.
#
# This is ON PURPOSE. Do not copy this pattern into real code.
# =============================================================================
import os
import math
import random
import hashlib
from functools import wraps
from flask import (Flask, request, session, redirect, url_for,
                   render_template, abort, flash, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-not-secret-polaris")

# Where the legit reports live. Depth matters for the lab: /app/data/reports is
# three levels below "/", so "../../../private_folder/flag.txt" lands on the flag.
REPORTS_DIR = os.path.join(app.root_path, "data", "reports")
FLAG_HINT = "/private_folder/flag.txt"

# Bundled walkthrough + solution pages (copied into the image by the Dockerfile).
TUTORIAL_DIR = os.path.join(app.root_path, "tutorial")

# In-memory user store (resets when the container restarts -- fine for a lab).
USERS = {}

# --------------------------------------------------------------------------- #
#  Fake data for the dashboard + SOC (all invented; no real systems).
# --------------------------------------------------------------------------- #
CLOUD_SERVICES = [
    {"name": "web-prod-01",     "type": "Compute",  "region": "us-tex-1",  "spec": "4 vCPU / 8 GB",   "status": "running"},
    {"name": "web-prod-02",     "type": "Compute",  "region": "us-tex-1",  "spec": "4 vCPU / 8 GB",   "status": "running"},
    {"name": "api-gateway",     "type": "Compute",  "region": "us-east-2", "spec": "2 vCPU / 4 GB",   "status": "running"},
    {"name": "batch-worker",    "type": "Compute",  "region": "eu-west-1", "spec": "8 vCPU / 16 GB",  "status": "stopped"},
    {"name": "cust-records",    "type": "Database", "region": "us-tex-1",  "spec": "Postgres 15",     "status": "running"},
    {"name": "sessions-cache",  "type": "Database", "region": "us-tex-1",  "spec": "Redis 7",         "status": "running"},
    {"name": "polaris-backups", "type": "Storage",  "region": "us-tex-1",  "spec": "2.1 TB used",     "status": "running"},
    {"name": "public-assets",   "type": "Storage",  "region": "global",    "spec": "412 GB used",     "status": "running"},
]

# Reports shown on the Reports page (these files exist in REPORTS_DIR).
REPORTS = [
    {"file": "nov05.log", "label": "Nov 5  - Daily SOC summary",   "size": "4.1 KB"},
    {"file": "nov04.log", "label": "Nov 4  - Daily SOC summary",   "size": "3.8 KB"},
    {"file": "nov03.log", "label": "Nov 3  - Daily SOC summary",   "size": "3.9 KB"},
    {"file": "access.log","label": "Edge access log (last 24h)",   "size": "7.2 KB"},
]

# SOC alerts table. eid = stable event id (drill-down key); kind = log template.
ALERTS = [
    {"eid": "EVT-48213", "time": "11:42:07", "ago": "2m",  "sev": "critical", "source": "203.0.113.47",  "rule": "Multiple failed logins then success", "asset": "api-gateway",   "kind": "bruteforce"},
    {"eid": "EVT-48198", "time": "11:38:55", "ago": "6m",  "sev": "high",     "source": "198.51.100.9",  "rule": "Outbound data spike to new host",     "asset": "cust-records",  "kind": "exfil"},
    {"eid": "EVT-47720", "time": "10:21:30", "ago": "1h",  "sev": "medium",   "source": "10.0.4.19",     "rule": "New admin account created",           "asset": "web-prod-01",   "kind": "newadmin"},
    {"eid": "EVT-47611", "time": "09:14:02", "ago": "2h",  "sev": "high",     "source": "203.0.113.47",  "rule": "Port scan detected",                  "asset": "web-prod-02",   "kind": "portscan"},
    {"eid": "EVT-47402", "time": "08:51:48", "ago": "3h",  "sev": "low",      "source": "10.0.4.7",      "rule": "TLS certificate expiring soon",       "asset": "public-assets", "kind": "certexpiry"},
    {"eid": "EVT-47310", "time": "07:30:11", "ago": "4h",  "sev": "medium",   "source": "192.0.2.77",    "rule": "Geo-anomaly: login from new country", "asset": "api-gateway",   "kind": "geoanomaly"},
]

# Internal asset -> IP map (fictional, for netflow + event detail realism).
INTERNAL_HOSTS = {
    "edge-waf": "10.0.0.2", "api-gateway": "10.0.1.10", "web-prod-01": "10.0.2.11",
    "web-prod-02": "10.0.2.12", "batch-worker": "10.0.2.40", "cust-records": "10.0.3.20",
    "sessions-cache": "10.0.3.21", "polaris-backups": "10.0.3.40", "public-assets": "10.0.5.8",
}

# Assets reachable from the internet (drives exposure + posture on the detail page).
PUBLIC_ASSETS = {"api-gateway", "public-assets"}

SEVERITY = [  # (label, count, color-var) -- sums to 223 (believable, not a round 100)
    ("Critical", 3,   "crit"),
    ("High",     18,  "high"),
    ("Medium",   52,  "warn"),
    ("Low",      150, "ok"),
]

# Events per hour over the last 24h (fake).
EVENTS_24H = [12, 9, 7, 6, 8, 14, 22, 31, 44, 51, 48, 55,
              60, 57, 49, 46, 52, 63, 71, 58, 40, 29, 20, 15]

TOP_SOURCES = [  # (ip, events)
    ("203.0.113.47", 182),
    ("198.51.100.9", 141),
    ("192.0.2.77",   98),
    ("10.0.4.19",    67),
    ("10.0.4.7",     39),
]

DATA_FLOWS = [  # pipeline stages for the flow diagram
    "Internet", "Edge WAF", "api-gateway", "cust-records", "polaris-backups",
]

# KPI tiles: value, 24h spark series, delta vs yesterday, tone, and bullet (val/target/max).
KPIS = [
    {"key": "events",   "label": "Events (24h)",  "value": "{:,}".format(sum(EVENTS_24H)),
     "spark": EVENTS_24H, "delta": "+12%", "dir": "up",   "tone": "accent",
     "bullet": {"val": 742, "target": 800, "max": 1000}},
    {"key": "critical", "label": "Critical alerts", "value": "3",
     "spark": [0,0,1,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0], "delta": "-1", "dir": "down", "tone": "crit",
     "bullet": {"val": 3, "target": 2, "max": 8}},
    {"key": "blocked",  "label": "Threats blocked", "value": "1,473",
     "spark": [40,52,48,61,58,70,66,74,80,77,85,92,88,96,101,97,110,118,124,120,131,128,140,137], "delta": "+8%", "dir": "up", "tone": "ok",
     "bullet": {"val": 1473, "target": 1200, "max": 1600}},
    {"key": "egress",   "label": "Data egress", "value": "2.4 GB",
     "spark": [1.1,1.0,0.9,1.0,1.2,1.3,1.5,1.4,1.6,1.8,1.7,1.9,2.0,1.9,2.1,2.0,2.2,2.3,2.6,2.4,2.2,2.0,1.9,1.8], "delta": "+0.3 GB", "dir": "up", "tone": "warn",
     "bullet": {"val": 24, "target": 20, "max": 40}},
]

# HOME node for the Nightwatch threat map (equirectangular, viewBox 1000x460).
# The attack arcs are generated live in the browser (see app.js initThreatMap).
# All coordinates & IPs are fictional (TEST-NET / RFC5737, RFC1918).
THREAT_HOME = {"x": 258, "y": 212, "label": "us-tex-1"}

# --------------------------------------------------------------------------- #
#  Chart geometry helpers (hand-built SVG -- no external chart library).
# --------------------------------------------------------------------------- #
def line_points(values, w=620, h=170, pad=10):
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    n = len(values)
    step = (w - 2 * pad) / (n - 1)
    pts = []
    for i, v in enumerate(values):
        x = pad + i * step
        y = h - pad - (v - lo) / span * (h - 2 * pad)
        pts.append((round(x, 1), round(y, 1)))
    return pts

def spark_path(values, w=132, h=36, pad=3):
    """Return (polyline, area, last_point) for a tiny KPI sparkline."""
    pts = line_points(values, w=w, h=h, pad=pad)
    poly = " ".join(f"{x},{y}" for x, y in pts)
    area = f"M{pts[0][0]},{h-pad} " + " ".join(f"L{x},{y}" for x, y in pts) + f" L{pts[-1][0]},{h-pad} Z"
    return {"poly": poly, "area": area, "last": pts[-1], "w": w, "h": h}

def anomalies(values, pts, k=1.2):
    """Indices whose value exceeds mean + k*stddev -> flagged spikes."""
    n = len(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    std = math.sqrt(var)
    out = []
    for i, v in enumerate(values):
        if v >= mean + k * std:
            x, y = pts[i]
            out.append({"i": i, "x": x, "y": y, "v": v, "hour": f"{i:02d}:00"})
    return out

def donut_segments(severity):
    total = sum(c for _, c, _ in severity) or 1
    circ = 2 * math.pi * 52  # r = 52
    segs, offset = [], 0.0
    for label, count, color in severity:
        frac = count / total
        length = frac * circ
        segs.append({"label": label, "count": count, "color": color,
                     "dash": round(length, 2), "gap": round(circ - length, 2),
                     "offset": round(-offset, 2), "pct": round(frac * 100)})
        offset += length
    return segs, total

# --------------------------------------------------------------------------- #
#  SIEM drill-down generators (deterministic fake data; all fictional)
# --------------------------------------------------------------------------- #
def _rng(seed_str):
    r = random.Random()
    r.seed(int(hashlib.md5(seed_str.encode()).hexdigest()[:12], 16))
    return r

def _t2s(t):
    h, m, s = (int(x) for x in t.split(":"))
    return h * 3600 + m * 60 + s

def _s2t(x):
    x %= 86400
    return "%02d:%02d:%02d" % (x // 3600, (x % 3600) // 60, x % 60)

def _human_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024
    return "%.1f PB" % n

def gen_alert_events(alert):
    """Believable raw log lines leading up to an alert, themed to its kind."""
    r = _rng("alert:" + alert["eid"])
    ip, asset, kind = alert["source"], alert["asset"], alert["kind"]
    host = INTERNAL_HOSTS.get(asset, "10.0.0.9")
    lines = []  # (level, component, message)

    if kind == "bruteforce":
        users = ["root", "admin", "deploy", "svc_backup", "oracle", "jenkins", "ubuntu", "postgres", "git"]
        nfail = r.randint(11, 17)
        for _ in range(nfail):
            lines.append(("WARN", "sshd", "Failed password for %s from %s port %d ssh2"
                          % (r.choice(users), ip, r.randint(20000, 65000))))
        u = r.choice(["deploy", "svc_backup"])
        lines.append(("ALERT", "sshd", "Accepted password for %s from %s port %d ssh2" % (u, ip, r.randint(20000, 65000))))
        lines.append(("INFO", "systemd-logind", "New session %d of user %s." % (r.randint(200, 900), u)))
        lines.append(("WARN", "sudo", "%s : TTY=pts/1 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/bin/id" % (u, u)))
        lines.append(("ALERT", "nightwatch", "rule 'failed-then-success' matched: %d failures then success from %s on %s" % (nfail, ip, asset)))

    elif kind == "exfil":
        dst = "198.51.100.9"
        for _ in range(r.randint(9, 13)):
            lines.append(("INFO", "pgbouncer", "client %s connection to %s:%d established" % (host, dst, r.choice([443, 8443, 9000]))))
            kb = r.randint(80, 950) * r.randint(1, 8)
            lines.append(("WARN", "netflow", "egress %d KB  %s -> %s" % (kb, host, dst)))
        lines.append(("ALERT", "dlp", "outbound volume from %s to %s exceeds 24h baseline by %d%%" % (asset, dst, r.randint(410, 1300))))
        lines.append(("ALERT", "nightwatch", "rule 'egress-spike-new-host' matched: first contact with %s today" % dst))

    elif kind == "newadmin":
        newu = r.choice(["svc_deploy2", "jdoe_adm", "backup_op", "ops_temp"])
        lines.append(("INFO", "auth", "session opened for user admin from %s" % ip))
        lines.append(("NOTICE", "useradd", "new user: name=%s, UID=%d, GID=27, home=/home/%s" % (newu, r.randint(1500, 1999), newu)))
        lines.append(("WARN", "usermod", "add '%s' to group 'sudo'" % newu))
        lines.append(("WARN", "usermod", "add '%s' to group 'wheel'" % newu))
        lines.append(("INFO", "passwd", "password for '%s' changed by 'admin'" % newu))
        for _ in range(r.randint(3, 6)):
            lines.append(("INFO", "audit", "USER_ACCT pid=%d uid=0 msg='op=PAM:accounting acct=\"%s\" exe=\"/usr/sbin/sshd\"'" % (r.randint(1000, 9999), newu)))
        lines.append(("ALERT", "nightwatch", "rule 'privileged-account-created' matched on %s (actor %s)" % (asset, ip)))

    elif kind == "portscan":
        for _ in range(r.randint(14, 22)):
            lines.append(("INFO", "ufw", "[UFW BLOCK] SRC=%s DST=%s PROTO=TCP SPT=%d DPT=%d SYN"
                          % (ip, host, r.randint(20000, 65000), r.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]))))
        lines.append(("WARN", "suricata", "ET SCAN Potential SSH Scan from %s (%d ports / 10s)" % (ip, r.randint(60, 240))))
        lines.append(("ALERT", "nightwatch", "rule 'horizontal-port-scan' matched: %s probed %s" % (ip, asset)))

    elif kind == "certexpiry":
        days = r.randint(6, 14)
        lines.append(("INFO", "cert-monitor", "checking certificate chain for %s" % asset))
        lines.append(("INFO", "cert-monitor", "leaf CN=assets.polariscloud.example issuer=Polaris Internal CA"))
        lines.append(("WARN", "cert-monitor", "certificate for %s expires in %d days (%s)" % (asset, days, "notAfter 2025-11-%02d" % r.randint(15, 28))))
        lines.append(("INFO", "cert-monitor", "OCSP status: good; chain length 2; keylen 2048"))
        lines.append(("NOTICE", "nightwatch", "rule 'tls-expiry-warning' matched on %s (%d days left)" % (asset, days)))

    else:  # geoanomaly
        country = r.choice(["RO", "BR", "NG", "SG", "VN"])
        lines.append(("INFO", "auth", "Accepted publickey for ops from %s port %d" % (ip, r.randint(20000, 65000))))
        lines.append(("WARN", "geoip", "login for 'ops' from %s geolocated to %s (new country for this account)" % (ip, country)))
        lines.append(("WARN", "geoip", "previous login 41m ago from 10.0.4.0/24 (us-tex-1)"))
        lines.append(("INFO", "device", "new device fingerprint for 'ops': ua=curl/8.4.0 tls=JA3/771..."))
        lines.append(("ALERT", "nightwatch", "rule 'impossible-travel' matched for 'ops' (%s -> %s)" % ("us-tex-1", country)))

    # assign ascending timestamps ending at the alert time
    end = _t2s(alert["time"])
    span = r.randint(70, 170)
    offsets = sorted(r.randint(0, span) for _ in lines)
    events = []
    for (lvl, comp, msg), off in zip(lines, offsets):
        ms = r.randint(0, 999)
        events.append({"t": "%s.%03d" % (_s2t(end - span + off), ms), "lvl": lvl,
                       "comp": comp, "src": ip, "msg": msg})
    events.sort(key=lambda e: e["t"])
    return events

def gen_netflow(ip):
    """Fake NetFlow v5-style records between `ip` and internal hosts."""
    r = _rng("flow:" + ip)
    peers = list(INTERNAL_HOSTS.values())
    rows, total_bytes, peerset = [], 0, set()
    base = _t2s("11:42:00")
    for _ in range(r.randint(18, 26)):
        peer = r.choice(peers); peerset.add(peer)
        out = r.random() < 0.5
        proto = r.choice(["TCP", "TCP", "TCP", "UDP"])
        sport = r.randint(1024, 65535)
        dport = r.choice([80, 443, 443, 8443, 22, 5432, 6379, 53, 9000])
        pkts = r.randint(3, 4200)
        byts = pkts * r.randint(44, 1480)
        total_bytes += byts
        flags = r.choice([".AP.SF", "....S.", ".AP...", ".A..SF", "...R..", ".APRSF"]) if proto == "TCP" else "......"
        dur = round(r.uniform(0.01, 42.0), 2)
        t = _s2t(base - r.randint(0, 3000))
        src = "%s:%d" % (ip, sport) if out else "%s:%d" % (peer, sport)
        dst = "%s:%d" % (peer, dport) if out else "%s:%d" % (ip, dport)
        rows.append({"t": t, "dur": "%.2fs" % dur, "proto": proto, "src": src, "dst": dst,
                     "pkts": pkts, "bytes": _human_bytes(byts), "raw_bytes": byts,
                     "flags": flags, "dir": "out" if out else "in"})
    rows.sort(key=lambda x: x["t"], reverse=True)
    summary = {"flows": len(rows), "bytes": _human_bytes(total_bytes), "peers": len(peerset)}
    return rows, summary

_TONE_COLOR = {"accent": "#F5A524", "ok": "#36D399", "": "#2DD4BF"}
_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

def gen_asset_detail(service):
    """Deterministic, fictional asset telemetry for a single cloud service.

    Pure in-memory/generated data -- NO filesystem access -- so the only
    vulnerability in this app stays the /show-report traversal.
    """
    name, t = service["name"], service["type"]
    r = _rng("asset:" + name)
    running = service["status"] == "running"
    ip = INTERNAL_HOSTS.get(name, "10.0.9.%d" % r.randint(2, 250))
    exposure = "public" if name in PUBLIC_ASSETS else "private"

    def series(lo, hi, n=24, j=0.16, as_int=False):
        v = r.uniform(lo, hi)
        out = []
        for _ in range(n):
            v += r.uniform(-(hi - lo) * j, (hi - lo) * j)
            v = max(lo, min(hi, v))
            out.append(round(v) if as_int else round(v, 1))
        return out

    # ---- health metrics, tailored to the asset type ----
    if t == "Compute":
        raw = [("CPU", "%", "accent", series(8, 72)),
               ("Memory", "%", "", series(32, 80)),
               ("Network", " Mbps", "ok", series(2, 160, as_int=True))]
    elif t == "Database":
        raw = [("Connections", "", "accent", series(12, 140, as_int=True)),
               ("IOPS", "", "", series(200, 5200, as_int=True)),
               ("Cache hit", "%", "ok", series(88, 99))]
    else:  # Storage
        raw = [("Capacity", "%", "accent", series(44, 78)),
               ("Throughput", " MB/s", "", series(10, 240, as_int=True)),
               ("Requests", "/s", "ok", series(20, 900, as_int=True))]
    metrics = []
    for label, unit, tone, ser in raw:
        last = ser[-1]
        disp = "{:,}".format(last) if isinstance(last, int) else ("%g" % last)
        metrics.append({"label": label, "tone": tone, "color": _TONE_COLOR[tone],
                        "value": "—" if not running else disp + unit,
                        "spark": spark_path(ser)})

    # ---- identity / metadata ----
    image = {"Compute": "Ubuntu 22.04 LTS (x86_64)",
             "Database": service["spec"],
             "Storage": "Object store · S3-compatible"}[t]
    region = service["region"]
    az = "multi-az" if region == "global" else region + r.choice(["a", "b", "c"])
    identity = {
        "resource_id": "res-" + hashlib.md5(name.encode()).hexdigest()[:10],
        "ip": ip, "image": image, "region": region, "zone": az, "spec": service["spec"],
        "exposure": exposure,
        "owner": r.choice(["team-platform", "team-data", "team-sre", "team-web"]),
        "created": "2025-%02d-%02d" % (r.randint(1, 9), r.randint(1, 28)),
        "uptime": ("%dd %dh" % (r.randint(3, 210), r.randint(0, 23))) if running else "—",
        "encryption": "AES-256 (at rest)",
    }

    # ---- listening services / open ports ----
    if t == "Compute":
        ports = [{"port": 22, "svc": "sshd", "exp": "internal"},
                 {"port": 443, "svc": "nginx", "exp": exposure},
                 {"port": 9100, "svc": "node-exporter", "exp": "internal"}]
    elif t == "Database":
        if "Redis" in service["spec"]:
            ports = [{"port": 6379, "svc": "redis-server", "exp": "internal"}]
        else:
            ports = [{"port": 5432, "svc": "postgres", "exp": "internal"},
                     {"port": 9187, "svc": "postgres-exporter", "exp": "internal"}]
    else:
        ports = [{"port": 443, "svc": "object-gateway", "exp": exposure},
                 {"port": 80, "svc": "http-redirect", "exp": exposure}]

    # ---- security posture ----
    related = [a for a in ALERTS if a["asset"] == name]
    top_sev = max((a["sev"] for a in related), key=lambda s: _SEV_RANK[s], default=None)
    findings = r.randint(0, 4) if exposure == "public" else r.randint(0, 2)
    posture = {
        "open_alerts": len(related), "top_sev": top_sev,
        "exposure": exposure,
        "last_scan": "2025-11-%02d" % r.randint(1, 5),
        "findings": findings,
        "patch": "current" if r.random() < 0.5 else "%d updates pending" % r.randint(1, 6),
    }

    return {"metrics": metrics, "identity": identity, "ports": ports,
            "posture": posture, "related": related}

# --------------------------------------------------------------------------- #
#  Auth plumbing
# --------------------------------------------------------------------------- #
def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped

@app.context_processor
def inject_globals():
    return {"current_user": session.get("user"), "flag_hint": FLAG_HINT}

# --------------------------------------------------------------------------- #
#  Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def landing():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        if not u or not p:
            flash("Username and password are required.", "error")
        elif u in USERS:
            flash("That username is already registered. Try signing in.", "error")
        else:
            USERS[u] = generate_password_hash(p)
            session["user"] = u
            return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        if u in USERS and check_password_hash(USERS[u], p):
            session["user"] = u
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)
        flash("Invalid credentials. New here? Create an account.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))

@app.route("/dashboard")
@login_required
def dashboard():
    counts = {
        "compute": sum(1 for s in CLOUD_SERVICES if s["type"] == "Compute"),
        "database": sum(1 for s in CLOUD_SERVICES if s["type"] == "Database"),
        "storage": sum(1 for s in CLOUD_SERVICES if s["type"] == "Storage"),
        "running": sum(1 for s in CLOUD_SERVICES if s["status"] == "running"),
    }
    # small spark for each service-type tile
    tiles = [
        {"k": "Compute",   "v": counts["compute"],  "tone": "accent", "spark": spark_path([2,3,3,4,4,4,4])},
        {"k": "Databases", "v": counts["database"], "tone": "",       "spark": spark_path([1,1,2,2,2,2,2])},
        {"k": "Storage",   "v": counts["storage"],  "tone": "",       "spark": spark_path([1,2,2,2,2,2,2])},
        {"k": "Running",   "v": f'{counts["running"]}/{len(CLOUD_SERVICES)}', "tone": "ok", "spark": spark_path([6,6,7,7,6,7,7])},
    ]
    return render_template("dashboard.html", services=CLOUD_SERVICES, tiles=tiles)

@app.route("/dashboard/service/<name>")
@login_required
def service_detail(name):
    service = next((s for s in CLOUD_SERVICES if s["name"] == name), None)
    if service is None:
        abort(404)
    d = gen_asset_detail(service)
    return render_template("service_detail.html", s=service, d=d,
                           related=d["related"], ip=d["identity"]["ip"])

@app.route("/siem")
@login_required
def siem():
    segs, total_alerts = donut_segments(SEVERITY)
    pts = line_points(EVENTS_24H)
    polyline = " ".join(f"{x},{y}" for x, y in pts)
    area = f"M{pts[0][0]},160 " + " ".join(f"L{x},{y}" for x, y in pts) + f" L{pts[-1][0]},160 Z"
    anoms = anomalies(EVENTS_24H, pts)
    max_src = max(c for _, c in TOP_SOURCES) or 1
    sources = [(ip, c, round(c / max_src * 100)) for ip, c in TOP_SOURCES]

    # KPI tiles with sparkline + bullet geometry
    kpis = []
    for k in KPIS:
        bl = k["bullet"]
        kpis.append({**k, "spark_svg": spark_path(k["spark"]),
                     "bullet_pct": round(bl["val"] / bl["max"] * 100),
                     "target_pct": round(bl["target"] / bl["max"] * 100)})

    stats = {"events": "{:,}".format(sum(EVENTS_24H)), "critical": SEVERITY[0][1],
             "blocked": 1473, "egress": "2.4 GB"}
    return render_template("siem.html", segs=segs, total_alerts=total_alerts,
                           polyline=polyline, area=area, points=pts, anomalies=anoms,
                           sources=sources, alerts=ALERTS, flows=DATA_FLOWS,
                           stats=stats, events=EVENTS_24H, kpis=kpis,
                           home=THREAT_HOME)

@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html", reports=REPORTS)

@app.route("/siem/alert/<eid>")
@login_required
def alert_detail(eid):
    alert = next((a for a in ALERTS if a["eid"] == eid), None)
    if alert is None:
        abort(404)
    events = gen_alert_events(alert)
    return render_template("alert_detail.html", alert=alert, events=events,
                           host=INTERNAL_HOSTS.get(alert["asset"]))

@app.route("/siem/source/<ip>")
@login_required
def source_netflow(ip):
    rows, summary = gen_netflow(ip)
    return render_template("netflow.html", ip=ip, rows=rows, summary=summary)

# --------------------------------------------------------------------------- #
#  Bundled walkthrough + solution pages (static HTML served from TUTORIAL_DIR).
#  send_from_directory uses werkzeug's safe_join, so these routes CANNOT be
#  traversed -- the only intentional traversal remains /show-report below.
# --------------------------------------------------------------------------- #
@app.route("/solution.html")
@login_required
def solution_page():
    return send_from_directory(TUTORIAL_DIR, "index.html")

@app.route("/index.html")          # back-links inside sub-page.html point here
@login_required
def tutorial_index():
    return send_from_directory(TUTORIAL_DIR, "index.html")

@app.route("/sub-page.html")
@login_required
def subpage():
    return send_from_directory(TUTORIAL_DIR, "sub-page.html")

@app.route("/assets/<path:fname>")
@login_required
def tutorial_assets(fname):
    return send_from_directory(os.path.join(TUTORIAL_DIR, "assets"), fname)

@app.route("/show-report")
@login_required
def show_report():
    report = request.args.get("report", "")
    if not report:
        return redirect(url_for("reports"))
    # ------------------------------------------------------------------ #
    #  >>> THE VULNERABILITY <<<
    #  User input is joined straight onto the reports directory and opened
    #  with no path validation. "../" escapes REPORTS_DIR. Never do this.
    # ------------------------------------------------------------------ #
    path = os.path.join(REPORTS_DIR, report)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        content = None
        err = str(e)
    else:
        err = None
    return render_template("report_view.html", report=report, content=content,
                           err=err, resolved=path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
