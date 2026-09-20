#!/usr/bin/env python3
"""
mobile-ping server.

Публичная часть: сайт, куда человек вводит адреса и получает матрицу
"устройство x цель". Приватная часть: очередь заданий для агентов,
которые физически переключаются между Wi-Fi точками телефонов.

Зависимостей нет — только стандартная библиотека.

Переменные окружения:
    MP_DB      путь к базе        (default ./mobile-ping.db)
    MP_PORT    порт               (default 8091)
    MP_HOST    адрес              (default 0.0.0.0)
    MP_TOKEN   токен агентов      (обязателен)
    MP_STATIC  каталог статики    (default ./static)
"""

import csv
import io as _io
import json
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("MP_DB", os.path.join(HERE, "mobile-ping.db"))
STATIC_DIR = os.environ.get("MP_STATIC", os.path.join(HERE, "static"))
PORT = int(os.environ.get("MP_PORT", "8091"))
HOST = os.environ.get("MP_HOST", "0.0.0.0")
TOKEN = os.environ.get("MP_TOKEN", "")

# Задание, которое агент взял и не трогает дольше этого времени, считается
# провалившимся: агент мог уйти в перезагрузку прямо на точке телефона.
JOB_LEASE_SEC = 30 * 60
# Агент, не подававший признаков жизни дольше этого, показывается офлайном.
AGENT_STALE_SEC = 120

MAX_TARGETS = 100
MAX_PORTS = 6

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    status       TEXT NOT NULL,          -- queued|running|done|failed
    note         TEXT,
    targets      TEXT NOT NULL,          -- json: список строк
    ports        TEXT NOT NULL,          -- json: список int
    icmp_count   INTEGER NOT NULL,
    devices_req  TEXT,                   -- json: список имён или null = все
    agent_id     TEXT,
    claimed_at   REAL,
    finished_at  REAL,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS device_runs (
    job_id       TEXT NOT NULL,
    device       TEXT NOT NULL,
    status       TEXT NOT NULL,          -- running|done|error|skipped
    ssid         TEXT,
    bssid        TEXT,
    signal       TEXT,
    local_ip     TEXT,
    gateway      TEXT,
    egress_ip    TEXT,
    egress_info  TEXT,
    egress_ok    INTEGER,                -- 1 = трафик точно ушёл мимо домашней сети
    started_at   REAL,
    finished_at  REAL,
    error        TEXT,
    PRIMARY KEY (job_id, device)
);

CREATE TABLE IF NOT EXISTS results (
    job_id       TEXT NOT NULL,
    device       TEXT NOT NULL,
    target       TEXT NOT NULL,
    resolved_ip  TEXT,
    icmp_sent    INTEGER,
    icmp_recv    INTEGER,
    rtt_min      REAL,
    rtt_avg      REAL,
    rtt_max      REAL,
    icmp_status  TEXT,
    tcp          TEXT,                   -- json: [{port, ok, ms, error}]
    error        TEXT,
    PRIMARY KEY (job_id, device, target)
);

-- Журнал агента по заданию: что он делал по шагам. Нужен, чтобы отличить
-- «цель молчит» от «агент не доехал до этой цели».
CREATE TABLE IF NOT EXISTS job_logs (
    job_id       TEXT NOT NULL,
    ts           REAL NOT NULL,
    seq          INTEGER NOT NULL,
    device       TEXT,
    text         TEXT NOT NULL,
    PRIMARY KEY (job_id, seq)
);

CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    devices      TEXT,                   -- json: [{name, ssid}]
    version      TEXT,
    state        TEXT,
    last_seen    REAL
);
"""


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


MIGRATIONS = [
    "ALTER TABLE jobs ADD COLUMN num INTEGER",
    "ALTER TABLE device_runs ADD COLUMN operator TEXT",
    "ALTER TABLE device_runs ADD COLUMN num INTEGER",
]


def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)
        for stmt in MIGRATIONS:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass          # колонка уже есть — обычный повторный запуск


_claim_lock = threading.Lock()


# --------------------------------------------------------------------------
# разбор пользовательского ввода
# --------------------------------------------------------------------------

HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,253}$")


def parse_targets(raw):
    """Строка/список -> список целей. Каждая цель: 'host' или 'host:port'."""
    if isinstance(raw, list):
        tokens = raw
    else:
        tokens = re.split(r"[\s,;]+", str(raw or ""))

    out, seen = [], set()
    for tok in tokens:
        tok = str(tok).strip()
        if not tok:
            continue
        if "://" in tok:                      # http://host/path -> host
            parsed = urlparse(tok)
            tok = parsed.netloc or parsed.path
        tok = tok.strip("/")
        if not tok:
            continue
        if not HOST_RE.match(tok):
            raise ValueError("недопустимый адрес: %r" % tok[:60])
        if tok.lower() in seen:
            continue
        seen.add(tok.lower())
        out.append(tok)
        if len(out) > MAX_TARGETS:
            raise ValueError("слишком много целей, максимум %d" % MAX_TARGETS)
    if not out:
        raise ValueError("не задано ни одной цели")
    return out


def parse_ports(raw):
    if raw is None or raw == "":
        return [443, 80]
    tokens = [str(x) for x in raw] if isinstance(raw, list) \
        else re.split(r"[\s,;]+", str(raw))
    out = []
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        try:
            port = int(tok)
        except ValueError:
            raise ValueError("порт не число: %r" % tok[:20])
        if not 1 <= port <= 65535:
            raise ValueError("порт вне диапазона: %d" % port)
        if port not in out:
            out.append(port)
        if len(out) > MAX_PORTS:
            raise ValueError("слишком много портов, максимум %d" % MAX_PORTS)
    return out


# --------------------------------------------------------------------------
# операции над заданиями
# --------------------------------------------------------------------------

def reap_stale_jobs(conn):
    now = time.time()
    conn.execute(
        "UPDATE jobs SET status='failed', error='агент не отвечал', "
        "finished_at=?, updated_at=? WHERE status='running' AND updated_at < ?",
        (now, now, now - JOB_LEASE_SEC),
    )


def store_logs(conn, job_id, lines):
    """
    Сложить строки журнала агента. Нумерация сквозная и назначается сервером:
    агент может слать одну и ту же пачку повторно, если связь оборвалась, и
    дубли не должны множиться.
    """
    if not lines:
        return
    row = conn.execute("SELECT MAX(seq) FROM job_logs WHERE job_id=?",
                       (job_id,)).fetchone()
    seq = (row[0] or 0) + 1
    seen = {r[0] for r in conn.execute(
        "SELECT text FROM job_logs WHERE job_id=?", (job_id,))}
    for line in lines[:2000]:
        if isinstance(line, dict):
            ts, text, device = line.get("ts"), line.get("text"), line.get("device")
        else:
            ts, text, device = None, line, None
        text = str(text or "")[:500]
        if not text or text in seen:
            continue
        seen.add(text)
        conn.execute(
            "INSERT OR IGNORE INTO job_logs (job_id, ts, seq, device, text) "
            "VALUES (?,?,?,?,?)",
            (job_id, float(ts) if ts else time.time(), seq,
             str(device)[:64] if device else None, text))
        seq += 1


def create_job(targets, ports, icmp_count, devices_req, note):
    job_id = uuid.uuid4().hex[:12]
    now = time.time()
    with db() as conn:
        # Человеку удобнее ссылаться на «проверку №7», чем на hex-идентификатор.
        row = conn.execute("SELECT MAX(num) FROM jobs").fetchone()
        num = (row[0] or 0) + 1
        conn.execute(
            "INSERT INTO jobs (id, num, created_at, updated_at, status, note, "
            "targets, ports, icmp_count, devices_req) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (job_id, num, now, now, "queued", note or "",
             json.dumps(targets), json.dumps(ports), icmp_count,
             json.dumps(devices_req) if devices_req else None),
        )
    return job_id, num


def job_to_dict(conn, job_id, with_results=True):
    row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None:
        return None
    job = {
        "id": row["id"],
        "num": row["num"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "finished_at": row["finished_at"],
        "status": row["status"],
        "note": row["note"],
        "targets": json.loads(row["targets"]),
        "ports": json.loads(row["ports"]),
        "icmp_count": row["icmp_count"],
        "devices_req": json.loads(row["devices_req"]) if row["devices_req"] else None,
        "agent_id": row["agent_id"],
        "error": row["error"],
    }
    if not with_results:
        return job

    job["devices"] = [dict(r) for r in conn.execute(
        "SELECT * FROM device_runs WHERE job_id=? "
        "ORDER BY COALESCE(num, 999), started_at", (job_id,))]
    results = {}
    for r in conn.execute("SELECT * FROM results WHERE job_id=?", (job_id,)):
        d = dict(r)
        d["tcp"] = json.loads(d["tcp"]) if d["tcp"] else []
        results.setdefault(d["device"], {})[d["target"]] = d
    job["results"] = results
    job["logs"] = [{"ts": r["ts"], "device": r["device"], "text": r["text"]}
                   for r in conn.execute(
                       "SELECT ts, device, text FROM job_logs WHERE job_id=? "
                       "ORDER BY seq", (job_id,))]
    return job


def job_to_csv(job):
    """
    Плоская таблица для анализа кодом: одна строка на (устройство, цель, порт).

    Длинный формат выбран намеренно: его без подготовки читают pandas, R и
    любая таблица, а колонки не разъезжаются при смене числа портов.
    """
    buf = _io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\n")
    w.writerow([
        "job_num", "job_id", "created_at", "note",
        "device", "device_num", "operator", "ssid", "device_status", "egress_ip",
        "egress_operator", "egress_ok", "local_ip",
        "target", "resolved_ip",
        "icmp_sent", "icmp_recv", "loss_pct", "rtt_min_ms", "rtt_avg_ms",
        "rtt_max_ms", "icmp_status",
        "port", "tcp_ok", "tcp_ms", "tls_ok", "tls_proto", "tls_error",
        "verdict", "error",
    ])

    created = iso(job.get("created_at"))
    by_device = {d["device"]: d for d in job.get("devices", [])}

    for device, targets in (job.get("results") or {}).items():
        d = by_device.get(device, {})
        for target in job.get("targets", []):
            r = targets.get(target)
            if not r:
                continue
            sent = r.get("icmp_sent") or 0
            recv = r.get("icmp_recv") or 0
            loss = round(100.0 * (sent - recv) / sent, 1) if sent else ""
            base = [
                job.get("num"), job.get("id"), created, job.get("note"),
                device, d.get("num") or "", d.get("operator") or "",
                d.get("ssid") or "",
                d.get("status") or "", d.get("egress_ip") or "",
                d.get("egress_info") or "",
                1 if d.get("egress_ok") else 0, d.get("local_ip") or "",
                target, r.get("resolved_ip") or "",
                sent, recv, loss,
                num(r.get("rtt_min")), num(r.get("rtt_avg")),
                num(r.get("rtt_max")), r.get("icmp_status") or "",
            ]
            tcp = r.get("tcp") or []
            if not tcp:
                w.writerow(base + ["", "", "", "", "", "",
                                   verdict(r), r.get("error") or ""])
                continue
            for t in tcp:
                w.writerow(base + [
                    t.get("port"), 1 if t.get("ok") else 0, num(t.get("ms")),
                    "" if t.get("tls") is None else (1 if t.get("tls") else 0),
                    t.get("tls_proto") or "", t.get("tls_error") or "",
                    verdict(r), r.get("error") or "",
                ])
    return buf.getvalue()


def num(x, digits=1):
    return "" if x is None else round(float(x), digits)


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)) if ts else ""


def verdict(r):
    """
    Короткий машинночитаемый итог по цели.

    blocked — TCP открывается, но TLS срывается: почерк DPI.
    ok      — отвечает хоть чем-то.
    no_icmp — жив по TCP, но не отвечает на ping.
    down    — не отвечает ничем.
    """
    if r.get("error"):
        return "error"
    tcp = r.get("tcp") or []
    tls_tried = [t for t in tcp if t.get("tls") is not None]
    if tls_tried and not any(t.get("tls") for t in tls_tried):
        return "blocked"
    icmp_ok = (r.get("icmp_recv") or 0) > 0
    tcp_ok = any(t.get("ok") for t in tcp)
    if icmp_ok and tcp_ok:
        return "ok"
    if tcp_ok:
        return "no_icmp"
    if icmp_ok:
        return "icmp_only"
    return "down"


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "mobile-ping/1.0"
    protocol_version = "HTTP/1.1"

    # -- утилиты ----------------------------------------------------------

    def _send(self, code, body=b"", ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _err(self, code, message):
        self._json(code, {"error": message})

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > 4 * 1024 * 1024:
            raise ValueError("тело запроса слишком большое")
        raw = self.rfile.read(length)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("тело запроса должно быть в UTF-8")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype == "application/x-www-form-urlencoded":
            return {k: v[-1] for k, v in parse_qs(text).items()}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise ValueError("тело запроса не JSON")

    def _authed(self):
        if not TOKEN:
            return False
        got = self.headers.get("Authorization", "")
        if got.startswith("Bearer "):
            got = got[7:]
        return got == TOKEN

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))
        sys.stderr.flush()

    # -- маршрутизация ----------------------------------------------------

    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method):
        path = urlparse(self.path).path.rstrip("/") or "/"
        query = parse_qs(urlparse(self.path).query)
        try:
            if method == "GET":
                if path == "/":
                    return self._static("index.html")
                if path.startswith("/j/"):
                    return self._static("job.html")
                if path == "/api/jobs":
                    return self._api_jobs_list()
                m = re.fullmatch(r"/api/jobs/([0-9a-f]{6,32})", path)
                if m:
                    return self._api_job_get(m.group(1))
                if path == "/api/agents":
                    return self._api_agents()
                if path == "/api/agent/poll":
                    return self._api_agent_poll(query)
                m = re.fullmatch(r"/api/jobs/([0-9a-f]{6,32})/export\.csv", path)
                if m:
                    return self._api_export_csv(m.group(1))
                if path == "/api":
                    return self._static("api.html")
                if path == "/api/whoami":
                    return self._api_whoami()
                if path == "/healthz":
                    return self._send(200, "ok", "text/plain; charset=utf-8")
                if path.startswith("/static/"):
                    return self._static(path[len("/static/"):])
                return self._err(404, "не найдено")

            if path == "/api/jobs":
                return self._api_job_create()
            if path == "/api/agent/hello":
                return self._api_agent_hello()
            m = re.fullmatch(r"/api/agent/jobs/([0-9a-f]{6,32})/device", path)
            if m:
                return self._api_agent_device(m.group(1))
            m = re.fullmatch(r"/api/agent/jobs/([0-9a-f]{6,32})/complete", path)
            if m:
                return self._api_agent_complete(m.group(1))
            return self._err(404, "не найдено")
        except ValueError as exc:
            return self._err(400, str(exc))
        except Exception as exc:  # сервер не должен падать из-за одного запроса
            self.log_message("ошибка на %s: %r", path, exc)
            return self._err(500, "внутренняя ошибка сервера")

    # -- статика ----------------------------------------------------------

    def _static(self, name):
        name = os.path.normpath(name).replace("\\", "/")
        if name.startswith("..") or name.startswith("/"):
            return self._err(403, "запрещено")
        full = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(full):
            return self._err(404, "не найдено")
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
        }.get(os.path.splitext(full)[1], "application/octet-stream")
        with open(full, "rb") as fh:
            return self._send(200, fh.read(), ctype)

    # -- публичный API ----------------------------------------------------

    def _api_job_create(self):
        data = self._body()
        targets = parse_targets(data.get("targets"))
        ports = parse_ports(data.get("ports"))
        try:
            icmp_count = int(data.get("icmp_count") or 4)
        except (TypeError, ValueError):
            raise ValueError("icmp_count не число")
        icmp_count = max(1, min(10, icmp_count))

        devices_req = data.get("devices") or None
        if isinstance(devices_req, str):
            devices_req = [d for d in re.split(r"[\s,;]+", devices_req) if d]
        note = str(data.get("note") or "")[:200]

        job_id, num = create_job(targets, ports, icmp_count, devices_req, note)
        return self._json(201, {"job_id": job_id, "num": num,
                                "url": "/j/" + job_id})

    def _api_whoami(self):
        """
        Внешний IP клиента. Агент спрашивает этот адрес через сокет,
        привязанный к Wi-Fi телефона, и так проверяет, что замер
        действительно уходит в мобильную сеть.
        """
        ip = self.client_address[0]
        # Доверяем X-Forwarded-For только от локального nginx.
        if ip in ("127.0.0.1", "::1"):
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                ip = fwd.split(",")[0].strip()
        return self._json(200, {"ip": ip})

    def _api_jobs_list(self):
        with db() as conn:
            reap_stale_jobs(conn)
            rows = conn.execute(
                "SELECT id, num, created_at, finished_at, status, note, targets, "
                "agent_id FROM jobs ORDER BY created_at DESC LIMIT 50").fetchall()
        return self._json(200, {"jobs": [
            {"id": r["id"], "num": r["num"], "created_at": r["created_at"],
             "finished_at": r["finished_at"], "status": r["status"],
             "note": r["note"], "agent_id": r["agent_id"],
             "targets": json.loads(r["targets"])}
            for r in rows]})

    def _api_job_get(self, job_id):
        with db() as conn:
            reap_stale_jobs(conn)
            job = job_to_dict(conn, job_id)
        if job is None:
            return self._err(404, "задание не найдено")
        return self._json(200, job)

    def _api_export_csv(self, job_id):
        with db() as conn:
            job = job_to_dict(conn, job_id)
        if job is None:
            return self._err(404, "задание не найдено")
        body = job_to_csv(job)
        # BOM — чтобы Excel открыл UTF-8 без плясок с кодировками
        raw = ("﻿" + body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition",
                         'attachment; filename="mobile-ping-%s.csv"'
                         % (job.get("num") or job_id))
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _api_agents(self):
        now = time.time()
        with db() as conn:
            rows = conn.execute("SELECT * FROM agents ORDER BY id").fetchall()
        return self._json(200, {"agents": [
            {"id": r["id"],
             "devices": json.loads(r["devices"]) if r["devices"] else [],
             "version": r["version"], "state": r["state"],
             "last_seen": r["last_seen"],
             "online": bool(r["last_seen"] and now - r["last_seen"] < AGENT_STALE_SEC)}
            for r in rows]})

    # -- API агента -------------------------------------------------------

    def _api_agent_hello(self):
        if not self._authed():
            return self._err(401, "нужен токен")
        data = self._body()
        agent_id = str(data.get("agent_id") or "").strip()[:64]
        if not agent_id:
            raise ValueError("agent_id обязателен")
        with db() as conn:
            conn.execute(
                "INSERT INTO agents (id, devices, version, state, last_seen) "
                "VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "devices=excluded.devices, version=excluded.version, "
                "state=excluded.state, last_seen=excluded.last_seen",
                (agent_id, json.dumps(data.get("devices") or [], ensure_ascii=False),
                 str(data.get("version") or "")[:32],
                 str(data.get("state") or "")[:200], time.time()),
            )
        return self._json(200, {"ok": True})

    def _api_agent_poll(self, query):
        if not self._authed():
            return self._err(401, "нужен токен")
        agent_id = (query.get("agent_id") or [""])[0].strip()[:64]
        if not agent_id:
            raise ValueError("agent_id обязателен")
        now = time.time()
        with _claim_lock:
            with db() as conn:
                reap_stale_jobs(conn)
                conn.execute("UPDATE agents SET last_seen=? WHERE id=?",
                             (now, agent_id))
                row = conn.execute(
                    "SELECT id FROM jobs WHERE status='queued' "
                    "ORDER BY created_at LIMIT 1").fetchone()
                if row is None:
                    return self._json(200, {"job": None})
                conn.execute(
                    "UPDATE jobs SET status='running', agent_id=?, claimed_at=?, "
                    "updated_at=? WHERE id=? AND status='queued'",
                    (agent_id, now, now, row["id"]))
                job = job_to_dict(conn, row["id"], with_results=False)
        return self._json(200, {"job": job})

    def _api_agent_device(self, job_id):
        """Частичный результат: один телефон отработал."""
        if not self._authed():
            return self._err(401, "нужен токен")
        data = self._body()
        device = str(data.get("device") or "").strip()[:64]
        if not device:
            raise ValueError("device обязателен")
        now = time.time()
        with db() as conn:
            if conn.execute("SELECT 1 FROM jobs WHERE id=?",
                            (job_id,)).fetchone() is None:
                return self._err(404, "задание не найдено")
            conn.execute(
                "INSERT INTO device_runs (job_id, device, operator, num, status, "
                "ssid, bssid, signal, local_ip, gateway, egress_ip, egress_info, "
                "egress_ok, started_at, finished_at, error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(job_id, device) DO UPDATE SET "
                "operator=excluded.operator, num=excluded.num, "
                "status=excluded.status, ssid=excluded.ssid, bssid=excluded.bssid, "
                "signal=excluded.signal, local_ip=excluded.local_ip, "
                "gateway=excluded.gateway, egress_ip=excluded.egress_ip, "
                "egress_info=excluded.egress_info, egress_ok=excluded.egress_ok, "
                "started_at=excluded.started_at, finished_at=excluded.finished_at, "
                "error=excluded.error",
                (job_id, device, str(data.get("operator") or "")[:64] or None,
                 data.get("num"),
                 str(data.get("status") or "done")[:16],
                 data.get("ssid"), data.get("bssid"), data.get("signal"),
                 data.get("local_ip"), data.get("gateway"), data.get("egress_ip"),
                 data.get("egress_info"),
                 1 if data.get("egress_ok") else 0,
                 data.get("started_at"), data.get("finished_at") or now,
                 data.get("error")))

            for res in (data.get("results") or []):
                conn.execute(
                    "INSERT INTO results (job_id, device, target, resolved_ip, "
                    "icmp_sent, icmp_recv, rtt_min, rtt_avg, rtt_max, icmp_status, "
                    "tcp, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(job_id, device, target) DO UPDATE SET "
                    "resolved_ip=excluded.resolved_ip, icmp_sent=excluded.icmp_sent, "
                    "icmp_recv=excluded.icmp_recv, rtt_min=excluded.rtt_min, "
                    "rtt_avg=excluded.rtt_avg, rtt_max=excluded.rtt_max, "
                    "icmp_status=excluded.icmp_status, tcp=excluded.tcp, "
                    "error=excluded.error",
                    (job_id, device, str(res.get("target"))[:253],
                     res.get("resolved_ip"), res.get("icmp_sent"),
                     res.get("icmp_recv"), res.get("rtt_min"), res.get("rtt_avg"),
                     res.get("rtt_max"), res.get("icmp_status"),
                     json.dumps(res.get("tcp") or [], ensure_ascii=False),
                     res.get("error")))

            store_logs(conn, job_id, data.get("logs"))
            conn.execute("UPDATE jobs SET updated_at=? WHERE id=?", (now, job_id))
        return self._json(200, {"ok": True})

    def _api_agent_complete(self, job_id):
        if not self._authed():
            return self._err(401, "нужен токен")
        data = self._body()
        now = time.time()
        status = "failed" if data.get("error") else "done"
        with db() as conn:
            cur = conn.execute(
                "UPDATE jobs SET status=?, finished_at=?, updated_at=?, error=? "
                "WHERE id=?",
                (status, now, now, data.get("error"), job_id))
            if cur.rowcount == 0:
                return self._err(404, "задание не найдено")
            store_logs(conn, job_id, data.get("logs"))
        return self._json(200, {"ok": True})


def main():
    if not TOKEN:
        sys.stderr.write("MP_TOKEN не задан — агенты не смогут подключиться\n")
    init_db()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    sys.stderr.write("mobile-ping слушает %s:%d, база %s\n" % (HOST, PORT, DB_PATH))
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
