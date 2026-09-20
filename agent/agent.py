# -*- coding: utf-8 -*-
"""
agent.py — агент mobile-ping на промежуточном сервере (ноутбук, Windows).

Что делает по кругу:
    1. спрашивает у VPS, нет ли задания;
    2. получив задание, по очереди подключается к Wi-Fi каждого телефона;
    3. на каждом телефоне проверяет, что выход в интернет действительно
       мобильный (сверяет внешний IP), и меряет цели: ICMP + TCP;
    4. возвращается в обычную сеть и отдаёт результаты на VPS.

Все замеры привязаны к исходному адресу Wi-Fi-адаптера (см. probe.py) — иначе
на машине с кабелем и VPN они уйдут мимо мобильной сети.

Запуск:
    python agent.py                     # рабочий режим
    python agent.py --selftest          # диагностика сети, ничего не меняет
    python agent.py --local 1.1.1.1 8.8.8.8   # прогон без сервера
    python agent.py --once              # обработать одно задание и выйти
"""

import argparse
import io
import json
import os
import sys
import time
import traceback
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import netinfo
import probe
import wifi_windows as wifi

VERSION = "1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "agent.config.json")
LOG_PATH = os.path.join(HERE, "agent.log")

DEFAULTS = {
    "server": "http://127.0.0.1:8091",
    "token": "",
    "agent_id": "agent",
    "wifi_adapter": None,
    "home": {"ssid": None, "password": None},
    "devices": [],
    "poll_interval": 5,
    "connect_timeout": 45,
    "dhcp_timeout": 30,
    "settle_sec": 3,
    "icmp_count": 4,
    "icmp_timeout_ms": 2000,
    "tcp_timeout": 3.0,
    "parallel": 4,
    "known_non_mobile_ips": [],
}


def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with io.open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def load_config(path=CONFIG_PATH):
    if not os.path.isfile(path):
        raise SystemExit(
            "нет файла настроек %s\n"
            "скопируйте agent.config.example.json и заполните его" % path)
    with io.open(path, encoding="utf-8") as fh:
        user = json.load(fh)
    cfg = dict(DEFAULTS)
    cfg.update(user)
    cfg["home"] = dict(DEFAULTS["home"], **(user.get("home") or {}))
    if not cfg["devices"]:
        raise SystemExit("в настройках не задано ни одного устройства (devices)")
    names = [d["name"] for d in cfg["devices"]]
    if len(names) != len(set(names)):
        raise SystemExit("имена устройств в devices должны быть уникальны")
    return cfg


# --------------------------------------------------------------------------
# обмен с сервером
# --------------------------------------------------------------------------

class Client:
    def __init__(self, base, token, timeout=20):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _call(self, method, path, body=None):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") \
            if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json",
                     "Connection": "close"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8") or "{}"
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise OSError("HTTP %d от сервера: %s" % (exc.code, detail))

    def hello(self, agent_id, devices, state):
        return self._call("POST", "/api/agent/hello",
                          {"agent_id": agent_id, "version": VERSION,
                           "state": state,
                           "devices": [{"name": d["name"], "ssid": d["ssid"]}
                                       for d in devices]})

    def poll(self, agent_id):
        return self._call("GET", "/api/agent/poll?agent_id=" + agent_id).get("job")

    def send_device(self, job_id, payload):
        return self._call("POST", "/api/agent/jobs/%s/device" % job_id, payload)

    def complete(self, job_id, error=None):
        return self._call("POST", "/api/agent/jobs/%s/complete" % job_id,
                          {"error": error})


# --------------------------------------------------------------------------
# замеры
# --------------------------------------------------------------------------

def measure(targets, src_ip, ports, icmp_count, icmp_timeout_ms, tcp_timeout,
            parallel):
    """Прогнать список целей с привязкой к src_ip. Порядок результатов сохраняется."""
    def one(t):
        try:
            return probe.probe_target(
                t, src_ip, ports=ports, icmp_count=icmp_count,
                icmp_timeout_ms=icmp_timeout_ms, tcp_timeout=tcp_timeout)
        except Exception as exc:
            return {"target": t, "error": "сбой замера: %s" % str(exc)[:80],
                    "tcp": []}

    with ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
        return list(pool.map(one, targets))


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.client = Client(cfg["server"], cfg["token"])
        self.adapter = netinfo.wifi_adapter(cfg.get("wifi_adapter"))
        self.adapter_name = self.adapter["name"]
        self.adapter_desc = self.adapter["description"]
        log("Wi-Fi адаптер: %s (idx=%d, %s)"
            % (self.adapter_name, self.adapter["index"], self.adapter_desc))

        tunnels = netinfo.routing_tunnels()
        if tunnels:
            log("внимание: подняты туннели — %s. Замеры привязываются к Wi-Fi, "
                "но внешний IP каждого устройства всё равно будет проверен."
                % ", ".join(t["name"] for t in tunnels))

    # -- сеть -----------------------------------------------------------

    def wifi_src_ip(self):
        a = netinfo.by_index(self.adapter["index"])
        return a["ipv4"][0] if a and a["ipv4"] else None

    def current_ssid(self):
        conn = wifi.current(self.adapter_desc)
        return (conn or {}).get("ssid")

    def connect_to(self, ssid, password, is_open=False):
        """
        Подключиться к сети.

        Профиль создаём только когда знаем, как в сеть заходить: есть пароль
        или сеть явно помечена открытой. Если ни того, ни другого — сеть уже
        заведена в Windows, и трогать её профиль нельзя: перезапись превратила
        бы домашнюю WPA2-сеть в открытую, и вернуться в неё стало бы невозможно.
        """
        before = self.wifi_src_ip()
        conn = wifi.join(ssid, self.adapter_name, password=password,
                         is_open=is_open, timeout=self.cfg["connect_timeout"],
                         description_contains=self.adapter_desc)
        a = wifi.wait_for_ip(self.adapter["index"],
                             timeout=self.cfg["dhcp_timeout"],
                             exclude_ip=before)
        time.sleep(self.cfg["settle_sec"])   # дать маршрутам устояться
        return conn, a

    def go_home(self):
        """Вернуться в обычную сеть. Вызывается в том числе из finally."""
        home = self.cfg["home"]
        if not home.get("ssid"):
            return
        try:
            if self.current_ssid() == home["ssid"]:
                return
            log("возвращаюсь в обычную сеть %r" % home["ssid"])
            self.connect_to(home["ssid"], home.get("password"),
                            bool(home.get("open")))
        except Exception as exc:
            log("не удалось вернуться в %r: %s" % (home["ssid"], str(exc)[:160]))

    def server_host(self):
        base = self.cfg["server"].split("//", 1)[-1]
        return base.split("/", 1)[0]

    def home_egress(self):
        """Внешний IP в обычной сети — эталон «это не мобильный интернет»."""
        try:
            src = self.wifi_src_ip()
            info = probe.egress_info(src, own_server=self.server_host()) \
                if src else {"ip": None, "info": ""}
            return info.get("ip")
        except Exception:
            return None

    # -- выполнение задания ---------------------------------------------

    def run_job(self, job):
        targets = job["targets"]
        ports = job.get("ports") or [443, 80]
        icmp_count = job.get("icmp_count") or self.cfg["icmp_count"]
        wanted = job.get("devices_req")
        devices = [d for d in self.cfg["devices"]
                   if not wanted or d["name"] in wanted]

        log("задание %s: %d целей, %d устройств, порты %s"
            % (job["id"], len(targets), len(devices), ports))
        if not devices:
            self.client.complete(job["id"], error="нет подходящих устройств")
            return

        not_mobile = set(self.cfg.get("known_non_mobile_ips") or [])
        home_ip = self.home_egress()
        if home_ip:
            not_mobile.add(home_ip)
            log("внешний IP обычной сети: %s" % home_ip)

        buffered = []
        job_error = None
        try:
            for dev in devices:
                payload = self.run_device(dev, job, targets, ports, icmp_count,
                                          not_mobile)
                try:
                    self.client.send_device(job["id"], payload)
                except OSError as exc:
                    log("сервер недоступен с этой сети (%s) — придержу результат"
                        % str(exc)[:80])
                    buffered.append(payload)
        except Exception as exc:
            job_error = str(exc)[:200]
            log("задание прервано: %s" % job_error)
            log(traceback.format_exc())
        finally:
            self.go_home()

        for payload in buffered:
            try:
                self.client.send_device(job["id"], payload)
                log("досланы результаты устройства %r" % payload["device"])
            except OSError as exc:
                log("не удалось дослать результаты %r: %s"
                    % (payload["device"], str(exc)[:100]))
                job_error = job_error or "часть результатов не доставлена"

        try:
            self.client.complete(job["id"], error=job_error)
        except OSError as exc:
            log("не удалось закрыть задание: %s" % str(exc)[:100])
        log("задание %s завершено" % job["id"])

    def run_device(self, dev, job, targets, ports, icmp_count, not_mobile):
        name, ssid = dev["name"], dev["ssid"]
        started = time.time()
        payload = {"device": name, "ssid": ssid, "started_at": started,
                   "status": "error", "results": []}

        try:
            self.client.send_device(job["id"], {
                "device": name, "ssid": ssid, "status": "running",
                "started_at": started, "results": []})
        except OSError:
            pass                                  # прогресс не критичен

        log("--- устройство %r: подключаюсь к %r" % (name, ssid))
        try:
            conn, adapter = self.connect_to(ssid, dev.get("password"),
                                            bool(dev.get("open")))
        except Exception as exc:
            # Не подключились — самое полезное, что можно сказать человеку:
            # видно ли точку вообще. «Не видна» и «видна, но не пускает» —
            # это две совершенно разные проблемы.
            hint = ""
            try:
                seen = [n for n in wifi.scan(self.adapter_desc)
                        if n["ssid"] == ssid]
                hint = (" точка видна, сигнал %d%%" % seen[0]["signal"]
                        if seen else " точки нет в эфире")
            except Exception:
                pass
            payload.update(error="не подключился: %s.%s" % (str(exc)[:140], hint),
                           finished_at=time.time())
            log("  не подключился: %s.%s" % (str(exc)[:140], hint))
            return payload

        src_ip = adapter["ipv4"][0]
        gw = adapter["gateways"][0] if adapter["gateways"] else None
        payload.update(bssid=conn.get("bssid"),
                       signal="%d%%" % conn.get("signal", 0),
                       local_ip=src_ip, gateway=gw)
        log("  подключён: IP %s, шлюз %s, сигнал %s"
            % (src_ip, gw, payload["signal"]))

        eg = probe.egress_info(src_ip, own_server=self.server_host())
        payload["egress_ip"] = eg.get("ip")
        payload["egress_info"] = eg.get("info")
        payload["egress_ok"] = bool(eg.get("ip") and eg["ip"] not in not_mobile)
        if payload["egress_ok"]:
            log("  внешний IP %s (%s) — мобильная сеть подтверждена"
                % (eg["ip"], eg.get("info") or "оператор неизвестен"))
        elif eg.get("ip"):
            log("  ВНИМАНИЕ: внешний IP %s совпадает с обычной сетью — "
                "трафик идёт не через телефон" % eg["ip"])
        else:
            log("  внешний IP определить не удалось (сеть режет доступ наружу)")

        # Адрес мог смениться, пока мы ходили за внешним IP. Замер с исчезнувшего
        # адреса молча превращается в «цель недоступна», поэтому проверяем.
        if not probe.source_usable(src_ip):
            fresh = netinfo.by_index(self.adapter["index"])
            new_ip = fresh["ipv4"][0] if fresh and fresh["ipv4"] else None
            if new_ip and probe.source_usable(new_ip):
                log("  адрес сменился %s -> %s, продолжаю" % (src_ip, new_ip))
                src_ip = new_ip
                payload["local_ip"] = new_ip
            else:
                payload.update(status="error", finished_at=time.time(),
                               error="исходный адрес пропал до начала замера — "
                                     "замер недействителен")
                log("  адрес %s исчез с адаптера, замер отменён" % src_ip)
                return payload

        payload["results"] = measure(
            targets, src_ip, ports, icmp_count, self.cfg["icmp_timeout_ms"],
            self.cfg["tcp_timeout"], self.cfg["parallel"])

        # Если замер развалился из-за исходного адреса, это сбой устройства, а
        # не приговор целям: показывать такое как «не отвечает» нельзя.
        invalid = [r for r in payload["results"] if probe.result_is_invalid(r)]
        if invalid and len(invalid) == len(payload["results"]):
            payload.update(status="error", finished_at=time.time(),
                           error="замер недействителен: исходный адрес %s "
                                 "пропал с адаптера" % src_ip)
            log("  ВНИМАНИЕ: замер недействителен, адрес %s пропал" % src_ip)
            return payload

        payload["status"] = "done"
        payload["finished_at"] = time.time()

        ok = sum(1 for r in payload["results"] if (r.get("icmp_recv") or 0) > 0)
        tcp_ok = sum(1 for r in payload["results"]
                     if any(t.get("ok") for t in (r.get("tcp") or [])))
        log("  готово за %d с: ICMP ответили %d из %d, TCP открыт у %d"
            % (payload["finished_at"] - started, ok, len(targets), tcp_ok))
        return payload

    # -- главный цикл ----------------------------------------------------

    def serve(self, once=False):
        log("агент %r запущен, сервер %s" % (self.cfg["agent_id"],
                                             self.cfg["server"]))
        idle = 0
        while True:
            try:
                self.client.hello(self.cfg["agent_id"], self.cfg["devices"],
                                  "сеть: %s" % (self.current_ssid() or "—"))
                job = self.client.poll(self.cfg["agent_id"])
            except OSError as exc:
                log("сервер недоступен: %s" % str(exc)[:120])
                time.sleep(max(5, self.cfg["poll_interval"]))
                continue

            if job:
                idle = 0
                self.run_job(job)
                if once:
                    return
            else:
                idle += 1
                if idle % 60 == 1:
                    log("заданий нет, жду")
                time.sleep(self.cfg["poll_interval"])


# --------------------------------------------------------------------------
# вспомогательные режимы
# --------------------------------------------------------------------------

def selftest(cfg):
    """Диагностика: что есть в системе и куда реально уходит трафик."""
    print("=== адаптеры ===")
    for a in netinfo.adapters():
        if a["up"] and a["ipv4"]:
            print("  %-34s idx=%-4d метрика=%-5d %s  шлюз %s"
                  % (a["name"][:34], a["index"], a["metric"],
                     ",".join(a["ipv4"]), ",".join(a["gateways"]) or "—"))

    tun = netinfo.routing_tunnels()
    print("\n=== туннели, способные перехватить трафик ===")
    print("  " + (", ".join(t["name"] for t in tun) if tun else "нет"))

    print("\n=== Wi-Fi ===")
    conn = wifi.current()
    print("  " + (("%s (сигнал %s%%, BSSID %s)"
                   % (conn.get("ssid"), conn.get("signal"), conn.get("bssid")))
                  if conn and conn.get("ssid") else "не подключён"))

    print("\n=== внешний IP по интерфейсам ===")
    for a in netinfo.adapters():
        if not (a["up"] and a["ipv4"] and a["gateways"]):
            continue
        src = a["ipv4"][0]
        eg = probe.egress_info(src, timeout=6)
        print("  %-34s %-15s -> %s  %s"
              % (a["name"][:34], src, eg["ip"] or "не определился", eg["info"]))

    print("\n=== настройки ===")
    print("  сервер:   %s" % cfg["server"])
    print("  агент:    %s" % cfg["agent_id"])
    print("  обычная сеть: %s" % (cfg["home"].get("ssid") or "не задана"))
    for d in cfg["devices"]:
        print("  устройство: %-16s SSID %r" % (d["name"], d["ssid"]))


def local_run(cfg, targets, ports, device_names=None):
    """Прогон без сервера: переключаемся по телефонам и печатаем таблицу."""
    agent = Agent(cfg)
    devices = [d for d in cfg["devices"]
               if not device_names or d["name"] in device_names]
    if not devices:
        raise SystemExit("подходящих устройств нет")

    not_mobile = set(cfg.get("known_non_mobile_ips") or [])
    home_ip = agent.home_egress()
    if home_ip:
        not_mobile.add(home_ip)
        print("внешний IP обычной сети: %s" % home_ip)

    fake_job = {"id": "local", "targets": targets, "ports": ports,
                "icmp_count": cfg["icmp_count"]}
    rows = []
    try:
        for dev in devices:
            payload = agent.run_device(dev, fake_job, targets, ports,
                                       cfg["icmp_count"], not_mobile)
            rows.append(payload)
    finally:
        agent.go_home()

    print("\n" + "=" * 78)
    for payload in rows:
        print("\nУСТРОЙСТВО %s — SSID %s, внешний IP %s %s"
              % (payload["device"], payload.get("ssid"),
                 payload.get("egress_ip") or "—",
                 "" if payload.get("egress_ok") else "(мобильный выход НЕ подтверждён)"))
        if payload.get("error"):
            print("  ошибка: %s" % payload["error"])
            continue
        for r in payload["results"]:
            icmp = ("%d/%d %s мс" % (r["icmp_recv"], r["icmp_sent"],
                                     round(r["rtt_avg"]) if r["rtt_avg"] else "—")
                    if r.get("icmp_sent") else (r.get("icmp_status") or "—"))
            tcp = " ".join("%d:%s" % (t["port"], "да" if t["ok"] else "нет")
                           for t in (r.get("tcp") or []))
            print("  %-28s ICMP %-16s TCP %s%s"
                  % (r["target"], icmp, tcp,
                     ("  " + r["error"]) if r.get("error") else ""))
    return rows


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace", line_buffering=True)
    ap = argparse.ArgumentParser(description="агент mobile-ping")
    ap.add_argument("--config", default=CONFIG_PATH)
    ap.add_argument("--selftest", action="store_true",
                    help="диагностика сети, ничего не переключает")
    ap.add_argument("--local", nargs="*", metavar="ЦЕЛЬ",
                    help="прогон без сервера по указанным целям")
    ap.add_argument("--ports", default="443,80")
    ap.add_argument("--devices", default=None,
                    help="какие устройства использовать, через запятую")
    ap.add_argument("--once", action="store_true",
                    help="обработать одно задание и выйти")
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.selftest:
        return selftest(cfg)

    if args.local is not None:
        if not args.local:
            raise SystemExit("укажите цели: --local 1.1.1.1 8.8.8.8")
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
        names = [d.strip() for d in args.devices.split(",")] \
            if args.devices else None
        return local_run(cfg, args.local, ports, names)

    agent = Agent(cfg)
    try:
        agent.serve(once=args.once)
    except KeyboardInterrupt:
        log("остановка по Ctrl+C")
        agent.go_home()


if __name__ == "__main__":
    main()
