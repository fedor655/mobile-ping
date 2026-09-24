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
import threading
import time
import traceback
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import netinfo
import probe

# Модуль Wi-Fi существует только под Windows: он построен на WLAN API и netsh.
# Импортируем его лениво, чтобы агент запускался под Linux, где точки Wi-Fi
# пока не поддерживаются, а телефоны подключаются кабелем.
wifi = None
if sys.platform == "win32":
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
    # Молчащая цель занимает поток ровно на icmp_count x icmp_timeout, и
    # ничего кроме ожидания не делает. Поэтому пропускная способность — это
    # parallel / (icmp_count x icmp_timeout), и упирается она в число потоков,
    # а не в канал: мобильный канал держит 3000 пингов в секунду без потерь.
    "parallel": 500,
    # А вот TCP так нельзя. Каждое соединение занимает запись в таблице NAT
    # телефона, и её размер невелик. Замер на Билайне: до 192 потоков неудач
    # нет, на 320 их уже 45%, на 500 — две трети. То есть выше порога замер
    # начинает врать про закрытые порты, а это худший вид ошибки: цифры идут,
    # выглядят правдоподобно и неверны.
    #
    # Значение выбрано по замеру стабильной скорости, а не по одному пику:
    # на 64 потоках разброс между прогонами невелик, выше он становится
    # трёхкратным. TLS-фаза самая медленная и она же определяет время полного
    # замера — на 64 потоках это 330 проверок в секунду по проводу, 140 через
    # телефон по кабелю и около 100 через его Wi-Fi.
    "parallel_tcp": 64,
    "known_non_mobile_ips": [],
}


# Пока выполняется задание, строки журнала копятся здесь и уезжают на сервер
# вместе с результатами: по одной таблице нельзя понять, почему цель молчала,
# а по журналу видно, дошёл ли агент до неё вообще.
_capture = None
_capture_lock = threading.Lock()
# Телефоны на кабеле меряются одновременно, поэтому «текущее устройство»
# у каждого потока своё, иначе строки журнала перемешаются между телефонами.
_local = threading.local()


def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with io.open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    with _capture_lock:
        if _capture is not None:
            _capture.append({"ts": time.time(),
                             "device": getattr(_local, "device", None),
                             "text": msg})


def start_capture():
    global _capture
    with _capture_lock:
        _capture = []
    _local.device = None


def stop_capture():
    global _capture
    with _capture_lock:
        _capture = None
    _local.device = None


def take_logs():
    """Забрать накопленное и очистить буфер."""
    global _capture
    with _capture_lock:
        if _capture is None:
            return []
        out, _capture = _capture, []
    return out


def peek_logs():
    """Копия накопленного, без очистки: сервер отбрасывает дубли по тексту,
    поэтому промежуточные отправки безопасны и журнал виден по ходу дела."""
    with _capture_lock:
        return list(_capture) if _capture is not None else []


def set_log_device(name):
    _local.device = name


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
                           "devices": [{"name": d["name"],
                                        "ssid": d.get("ssid") or d.get("adapter"),
                                        "operator": d.get("operator"),
                                        "link": "usb" if is_usb(d) else "wifi",
                                        "num": i + 1}
                                       for i, d in enumerate(devices)]})

    def poll(self, agent_id):
        return self._call("GET", "/api/agent/poll?agent_id=" + agent_id).get("job")

    def send_device(self, job_id, payload):
        return self._call("POST", "/api/agent/jobs/%s/device" % job_id, payload)

    def complete(self, job_id, error=None, logs=None):
        return self._call("POST", "/api/agent/jobs/%s/complete" % job_id,
                          {"error": error, "logs": logs or []})


# --------------------------------------------------------------------------
# замеры
# --------------------------------------------------------------------------

def measure(targets, src_ip, ports, icmp_count, icmp_timeout_ms, tcp_timeout,
            parallel_icmp, parallel_tcp, if_index=None):
    """Прогнать список целей. Порядок результатов сохраняется."""
    try:
        return probe.probe_many(
            targets, src_ip, ports=ports, icmp_count=icmp_count,
            icmp_timeout_ms=icmp_timeout_ms, tcp_timeout=tcp_timeout,
            parallel_icmp=parallel_icmp, parallel_tcp=parallel_tcp,
            if_index=if_index)
    except Exception as exc:
        return [{"target": t, "error": "сбой замера: %s" % str(exc)[:80],
                 "tcp": []} for t in targets]


def is_usb(dev):
    """Телефон подключён кабелем, а не раздаёт Wi-Fi."""
    return (dev.get("link") or "wifi").lower() == "usb"


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.client = Client(cfg["server"], cfg["token"])
        # Wi-Fi нужен, только если хоть одно устройство им пользуется. На
        # машине без беспроводного адаптера это не должно мешать работе
        # с телефонами на кабеле.
        self.adapter = None
        self.adapter_name = self.adapter_desc = None
        if any(not is_usb(d) for d in cfg["devices"]):
            if wifi is None:
                raise SystemExit(
                    "в настройках есть устройства по Wi-Fi, но переключение "
                    "точек поддержано только под Windows. На Linux "
                    "подключайте телефоны кабелем: link=usb.")
            self.adapter = netinfo.wifi_adapter(cfg.get("wifi_adapter"))
            self.adapter_name = self.adapter["name"]
            self.adapter_desc = self.adapter["description"]
            log("Wi-Fi адаптер: %s (idx=%d, %s)"
                % (self.adapter_name, self.adapter["index"], self.adapter_desc))

        bad = netinfo.capturing_tunnels()
        if bad:
            log("ВНИМАНИЕ: поднят полнотуннельный VPN — %s. Его маршруты "
                "перехватывают трафик раньше привязки к Wi-Fi, и замеры уйдут "
                "через него, а не через телефон. Отключите его, иначе каждое "
                "устройство будет отбраковано по внешнему адресу."
                % ", ".join(t["name"] for t in bad))
        other = [t for t in netinfo.routing_tunnels() if t not in bad]
        if other:
            log("подняты туннели %s — на замеры они не влияют, но внешний IP "
                "каждого устройства всё равно проверяется."
                % ", ".join(t["name"] for t in other))

    # -- сеть -----------------------------------------------------------

    def wifi_src_ip(self):
        a = netinfo.by_index(self.adapter["index"])
        return a["ipv4"][0] if a and a["ipv4"] else None

    def current_ssid(self):
        if wifi is None or not self.adapter_desc:
            return None
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
        if wifi is None or not home.get("ssid"):
            return
        try:
            if self.current_ssid() == home["ssid"]:
                return
            log("возвращаюсь в обычную сеть %r" % home["ssid"])
            self.connect_to(home["ssid"], home.get("password"),
                            bool(home.get("open")))
        except Exception as exc:
            log("не удалось вернуться в %r: %s" % (home["ssid"], str(exc)[:160]))

    @staticmethod
    def server_host_of(cfg):
        base = cfg["server"].split("//", 1)[-1]
        return base.split("/", 1)[0]

    def server_host(self):
        return self.server_host_of(self.cfg)

    BASELINE_TTL = 600

    def home_baseline(self, devices):
        """
        Внешние адреса всего, что не является телефоном, — эталон «это не
        мобильный интернет».

        Раньше эталон снимался только через Wi-Fi-адаптер. На машине без
        Wi-Fi-устройств (Linux, одни телефоны на кабеле) его не было вовсе, и
        проверка «не совпадает ли выход с домашним» молча отключалась. На
        боевой машине это дало «мобильная сеть подтверждена» для телефона,
        который раздавал домашний Wi-Fi.

        Теперь адрес снимается через каждый интерфейс со шлюзом, кроме самих
        телефонов, и отдельно через маршрут по умолчанию — со всеми прокси и
        VPN, что на нём стоят. Результат кэшируется: домашний адрес меняется
        редко, а замер стоит нескольких секунд.

        Возвращает словарь {откуда: внешний IP}.
        """
        cached = getattr(self, "_baseline", None)
        if cached and time.time() - cached[0] < self.BASELINE_TTL:
            return cached[1]

        phones = set()
        for d in devices:
            if is_usb(d):
                for a in netinfo.match_adapters(d.get("adapter")):
                    phones.add(a["name"])

        paths = [("маршрут по умолчанию", None, None)]
        for a in netinfo.adapters():
            ip = netinfo.usable_ipv4(a)
            if (a["up"] and ip and a["gateways"] and a["name"] not in phones
                    and not ip.startswith("127.")):
                paths.append((a["name"], ip, a["index"]))

        def one(path):
            label, src, idx = path
            try:
                eg = probe.egress_info(src, own_server=self.server_host(),
                                       if_index=idx, timeout=3, budget=5)
                return label, eg.get("ip")
            except Exception:
                return label, None

        with ThreadPoolExecutor(max_workers=len(paths)) as pool:
            found = {label: ip for label, ip in pool.map(one, paths) if ip}

        self._baseline = (time.time(), found)
        return found

    def baseline_to_set(self, devices):
        """Эталон одним множеством и запись в журнал — общее для двух режимов."""
        not_mobile = set(self.cfg.get("known_non_mobile_ips") or [])
        base = self.home_baseline(devices)
        for label, ip in sorted(base.items()):
            log("внешний IP обычной сети (%s): %s" % (label, ip))
            not_mobile.add(ip)
        if not base:
            log("ВНИМАНИЕ: внешний IP обычной сети не снялся ни через один "
                "интерфейс — проверка «не домашний ли это выход» не работает, "
                "и телефон, раздающий домашний Wi-Fi, не будет отбракован")
        return not_mobile

    # -- выполнение задания ---------------------------------------------

    def run_job(self, job):
        targets = job["targets"]
        ports = job.get("ports") or [443, 80]
        icmp_count = job.get("icmp_count") or self.cfg["icmp_count"]
        wanted = job.get("devices_req")
        devices = [d for d in self.cfg["devices"]
                   if not wanted or d["name"] in wanted]

        start_capture()
        log("задание %s: %d целей, %d устройств, порты %s"
            % (job["id"], len(targets), len(devices), ports))
        if not devices:
            self.client.complete(job["id"], error="нет подходящих устройств")
            return

        not_mobile = self.baseline_to_set(devices)

        numbered = list(enumerate(devices, start=1))
        by_usb = [(n, d) for n, d in numbered if is_usb(d)]
        by_wifi = [(n, d) for n, d in numbered if not is_usb(d)]

        buffered = []
        buffered_lock = threading.Lock()
        job_error = None

        def deliver(payload):
            """Отдать результат устройства; не дошло — придержать до дома."""
            payload["logs"] = take_logs()
            try:
                self.client.send_device(job["id"], payload)
            except OSError as exc:
                log("сервер недоступен с этой сети (%s) — придержу результат"
                    % str(exc)[:80])
                with buffered_lock:
                    buffered.append(payload)

        try:
            # Телефоны на кабеле независимы: у каждого свой адаптер,
            # переключать нечего. Поэтому меряем их одновременно, и обход
            # занимает столько же, сколько один телефон.
            if by_usb:
                log("по кабелю: %d устройств, меряю одновременно" % len(by_usb))
                with ThreadPoolExecutor(max_workers=len(by_usb)) as pool:
                    futures = [pool.submit(self.run_usb_device, dev, job,
                                           targets, ports, icmp_count,
                                           not_mobile, n)
                               for n, dev in by_usb]
                    for f in futures:
                        deliver(f.result())

            # Wi-Fi — строго по очереди: адаптер один на всех.
            for n, dev in by_wifi:
                deliver(self.run_wifi_device(dev, job, targets, ports,
                                             icmp_count, not_mobile, n))
        except Exception as exc:
            job_error = str(exc)[:200]
            log("задание прервано: %s" % job_error)
            log(traceback.format_exc())
        finally:
            set_log_device(None)
            if by_wifi:
                self.go_home()

        for payload in buffered:
            try:
                self.client.send_device(job["id"], payload)
                log("досланы результаты устройства %r" % payload["device"])
            except OSError as exc:
                log("не удалось дослать результаты %r: %s"
                    % (payload["device"], str(exc)[:100]))
                job_error = job_error or "часть результатов не доставлена"

        log("задание %s завершено" % job["id"])
        try:
            self.client.complete(job["id"], error=job_error, logs=take_logs())
        except OSError as exc:
            log("не удалось закрыть задание: %s" % str(exc)[:100])
        stop_capture()

    def check_egress(self, payload, src_ip, not_mobile, if_index=None):
        """
        Убедиться, что с этого адреса мы выходим именно в мобильную сеть.

        Возвращает True, если мерить можно. Иначе заполняет payload причиной:
        приватный внешний адрес означает перехват туннелем, совпадение с
        домашним — что канал вообще не тот. Общее для кабеля и Wi-Fi.
        """
        # Сначала — не подделывает ли кто-то трафик на этом пути вообще.
        # Если да, дальнейшие проверки бессмысленны: прокси ответит за кого
        # угодно, в том числе и за наш сервер.
        faked = probe.interception_check(src_ip, if_index)
        if faked:
            payload.update(status="error", finished_at=time.time(),
                           error="замер недействителен: " + faked)
            log("  ВНИМАНИЕ: %s Замер отменён." % faked)
            return False

        # TCP мы прибиваем к интерфейсу жёстко, а ICMP — нет: у
        # IcmpSendEcho2Ex есть только исходный адрес, маршрут выбирает ядро.
        # Из-за этого возможна худшая комбинация: внешний IP подтверждается
        # (он проверяется по TCP и потому верен), а пинги тихо уходят в
        # туннель. Спрашиваем у ядра заранее, куда оно их отправит.
        leak = probe.icmp_will_leak(src_ip)
        if leak:
            payload.update(status="error", finished_at=time.time(),
                           error="ICMP уйдут не через это устройство: ядро "
                                 "выбирает адрес %s. Обычно это поднятый "
                                 "полнотуннельный VPN — отключите его на "
                                 "машине агента." % leak)
            log("  ВНИМАНИЕ: ядро отправит ICMP с адреса %s, а не %s — "
                "замер отменён" % (leak, src_ip))
            return False

        eg = probe.egress_info(src_ip, own_server=self.server_host(),
                               if_index=if_index)
        egress_ip = eg.get("ip")
        payload["egress_ip"] = egress_ip
        payload["egress_info"] = eg.get("info")

        # Мобильный выход подтверждён, только если внешний адрес публичный и не
        # совпадает с обычной сетью. Приватный адрес означает, что запрос пришёл
        # на сервер из туннеля: на машине поднят VPN с маршрутами 0.0.0.0/1, и
        # он перехватывает трафик раньше, чем сработает привязка к адресу
        # интерфейса. Именно так заблокированный сайт кажется доступным.
        payload["egress_ok"] = bool(
            egress_ip and probe.is_public_ip(egress_ip)
            and egress_ip not in not_mobile)

        if payload["egress_ok"]:
            log("  внешний IP %s (%s) — мобильная сеть подтверждена"
                % (egress_ip, eg.get("info") or "оператор неизвестен"))
            return True
        if egress_ip and not probe.is_public_ip(egress_ip):
            payload.update(status="error", finished_at=time.time(),
                           error="трафик ушёл в туннель, а не через телефон: "
                                 "внешний адрес %s приватный. Отключите VPN на "
                                 "машине агента." % egress_ip)
            log("  ВНИМАНИЕ: внешний адрес %s приватный — трафик перехвачен "
                "туннелем, замер отменён" % egress_ip)
            return False
        if egress_ip:
            payload.update(status="error", finished_at=time.time(),
                           error="внешний IP %s совпадает с обычной сетью — "
                                 "замер шёл не через телефон" % egress_ip)
            log("  ВНИМАНИЕ: внешний IP %s совпадает с обычной сетью, "
                "замер отменён" % egress_ip)
            return False
        log("  внешний IP определить не удалось — за точкой нет интернета")
        return True

    def measure_into(self, payload, src_ip, targets, ports, icmp_count, job,
                     if_index=None):
        """Прогнать цели и разложить результат. Общее для кабеля и Wi-Fi."""
        started = payload["started_at"]
        payload["results"] = measure(
            targets, src_ip, ports, icmp_count,
            job.get("icmp_timeout_ms") or self.cfg["icmp_timeout_ms"],
            job.get("tcp_timeout") or self.cfg["tcp_timeout"],
            self.cfg["parallel"], self.cfg["parallel_tcp"], if_index)

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

    def report_running(self, job, payload):
        """Показать на сайте, что устройство взято в работу. Не критично."""
        if job.get("id") in (None, "local"):
            return
        try:
            probe_payload = dict(payload)
            probe_payload.update(status="running", results=[],
                                 logs=peek_logs())
            self.client.send_device(job["id"], probe_payload)
        except OSError:
            pass

    def run_usb_device(self, dev, job, targets, ports, icmp_count, not_mobile,
                       num=None):
        """
        Телефон на кабеле: переключать нечего, просто берём его адаптер.

        Отсюда и выигрыш — несколько таких телефонов меряются одновременно,
        а не по очереди, и заодно заряжаются.
        """
        name = dev["name"]
        set_log_device(name)
        started = time.time()
        payload = {"device": name, "operator": dev.get("operator"), "num": num,
                   "link": "usb", "ssid": dev.get("adapter"),
                   "started_at": started, "status": "error", "results": []}
        self.report_running(job, payload)

        pattern = dev.get("adapter")
        found = netinfo.match_adapters(pattern) if pattern else []
        if not found:
            payload.update(error="адаптер %r не найден: телефон отключён или "
                                 "выключен режим USB-модема" % pattern,
                           finished_at=time.time())
            log("--- устройство %r: адаптер %r не найден" % (name, pattern))
            return payload
        if len(found) > 1:
            # Молча взять первый — верный способ месяцами мерить не тот телефон.
            payload.update(error="описание %r подходит сразу нескольким "
                                 "адаптерам (%s). Укажите точное имя или MAC."
                                 % (pattern, ", ".join(a["name"] for a in found)),
                           finished_at=time.time())
            log("--- устройство %r: %r подходит нескольким: %s"
                % (name, pattern, ", ".join(a["name"] for a in found)))
            return payload

        adapter = found[0]
        src_ip = netinfo.usable_ipv4(adapter)
        if not src_ip:
            apipa = any(ip.startswith("169.254.") for ip in adapter["ipv4"])
            payload.update(error=("адаптер %s получил только адрес 169.254.x — "
                                  "телефон не выдал адрес по DHCP: переткните "
                                  "кабель или заново включите режим модема"
                                  % adapter["name"]) if apipa else
                                 ("у адаптера %s нет адреса: телефон не "
                                  "раздаёт интернет" % adapter["name"]),
                           finished_at=time.time())
            log("--- устройство %r: %s" % (name, payload["error"]))
            return payload
        payload.update(ssid=adapter["name"], local_ip=src_ip,
                       gateway=adapter["gateways"][0] if adapter["gateways"]
                       else None)
        log("--- устройство %r: кабель, адаптер %r, IP %s"
            % (name, adapter["name"], src_ip))

        if not probe.source_usable(src_ip):
            payload.update(error="адрес %s не годится для замера" % src_ip,
                           finished_at=time.time())
            return payload
        if not self.check_egress(payload, src_ip, not_mobile,
                                 adapter["index"]):
            return payload
        return self.measure_into(payload, src_ip, targets, ports, icmp_count,
                                 job, adapter["index"])

    def run_wifi_device(self, dev, job, targets, ports, icmp_count, not_mobile,
                        num=None):
        """Телефон, раздающий Wi-Fi: адаптер один, поэтому строго по очереди."""
        name, ssid = dev["name"], dev.get("ssid")
        set_log_device(name)
        started = time.time()
        payload = {"device": name, "ssid": ssid, "operator": dev.get("operator"),
                   "num": num, "link": "wifi", "started_at": started,
                   "status": "error", "results": []}
        self.report_running(job, payload)

        log("--- устройство %r: подключаюсь к %r" % (name, ssid))
        try:
            conn, adapter = self.connect_to(ssid, dev.get("password"),
                                            bool(dev.get("open")))
        except Exception as exc:
            # Не подключились — самое полезное, что можно сказать человеку:
            # видно ли точку вообще. «Не видна» и «видна, но не пускает» —
            # совершенно разные проблемы.
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

        if not self.check_egress(payload, src_ip, not_mobile,
                                 self.adapter["index"]):
            return payload

        # Адрес мог смениться, пока ходили за внешним IP: Wi-Fi только что
        # переподключался, и DHCP мог выдать другой.
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

        return self.measure_into(payload, src_ip, targets, ports, icmp_count,
                                 job, self.adapter["index"])

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
    conn = wifi.current() if wifi else None
    if wifi is None:
        print("  переключение точек Wi-Fi поддержано только под Windows; "
              "здесь телефоны подключаются кабелем")
    else:
        print("  " + (("%s (сигнал %s%%, BSSID %s)"
                       % (conn.get("ssid"), conn.get("signal"),
                          conn.get("bssid")))
                      if conn and conn.get("ssid") else "не подключён"))

    print("\n=== внешний IP и честность пути по интерфейсам ===")
    for a in netinfo.adapters():
        src = netinfo.usable_ipv4(a)
        if not (a["up"] and src and a["gateways"]):
            continue
        eg = probe.egress_info(src, own_server=Agent.server_host_of(cfg),
                               if_index=a["index"], timeout=3, budget=6)
        faked = probe.interception_check(src, a["index"], timeout=1.5)
        print("  %-22s %-15s -> %-15s %s"
              % (a["name"][:22], src, eg["ip"] or "не определился",
                 eg["info"][:30]))
        print("  %-22s %s" % ("", ("ПЕРЕХВАТ: " + faked) if faked
                               else "путь честный: несуществующий адрес не отвечает"))

    print("\n=== настройки ===")
    print("  сервер:   %s" % cfg["server"])
    print("  агент:    %s" % cfg["agent_id"])
    print("  обычная сеть: %s" % (cfg["home"].get("ssid") or "не задана"))
    for d in cfg["devices"]:
        if is_usb(d):
            a = netinfo.find_adapter(d.get("adapter"))
            print("  устройство: %-6s кабель, адаптер %-16r %s"
                  % (d["name"], d.get("adapter"),
                     (",".join(a["ipv4"]) or "без адреса") if a
                     else "НЕ НАЙДЕН"))
        else:
            print("  устройство: %-6s Wi-Fi,  точка %r" % (d["name"], d.get("ssid")))


def show_adapters(cfg):
    """
    Готовый кусок настроек по тому, что сейчас воткнуто в USB.

    Имя адаптера привязано к устройству и порту и переживает переподключение,
    поэтому опознаём по нему; MAC печатаем рядом как запасной вариант, если
    телефоны будут переставляться между портами.
    """
    usb = netinfo.usb_tethering_adapters()
    if not usb:
        print("Телефонов на кабеле не найдено. Включите на телефоне режим "
              "USB-модема и проверьте кабель.")
        return

    known = {d.get("adapter"): d for d in cfg["devices"] if is_usb(d)}
    print("Найдено телефонов на кабеле: %d" % len(usb))
    print("")
    lines = []
    for i, a in enumerate(usb, start=1):
        ip = netinfo.usable_ipv4(a)
        state = ip or ("только 169.254.x — DHCP не отработал"
                       if a["ipv4"] else "без адреса")
        mark = "уже в настройках" if a["name"] in known else "новый"
        print("  %-14s %-34s %-32s %s" % (a["name"], a["description"][:34],
                                          state, mark))
        print("      MAC %s" % a["mac"])
        lines.append('    {"name": "№%d", "operator": "?", "link": "usb", '
                     '"adapter": "%s"}' % (i, a["name"]))

    print("")
    print("Готовый блок devices для agent.config.json:")
    print("")
    print('  "devices": [')
    print(",\n".join(lines))
    print("  ]")
    print("")
    print("Поле operator заполните сами — это то, что видно на сайте.")


def local_run(cfg, targets, ports, device_names=None):
    """Прогон без сервера: переключаемся по телефонам и печатаем таблицу."""
    agent = Agent(cfg)
    devices = [d for d in cfg["devices"]
               if not device_names or d["name"] in device_names]
    if not devices:
        raise SystemExit("подходящих устройств нет")

    not_mobile = agent.baseline_to_set(devices)

    fake_job = {"id": "local", "targets": targets, "ports": ports,
                "icmp_count": cfg["icmp_count"], "icmp_timeout_ms": None,
                "tcp_timeout": None}
    rows = []
    try:
        for i, dev in enumerate(devices, start=1):
            run = agent.run_usb_device if is_usb(dev) else agent.run_wifi_device
            rows.append(run(dev, fake_job, targets, ports, cfg["icmp_count"],
                            not_mobile, i))
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
    ap.add_argument("--adapters", action="store_true",
                    help="телефоны на кабеле и готовый блок настроек")
    ap.add_argument("--local", nargs="*", metavar="ЦЕЛЬ",
                    help="прогон без сервера по указанным целям")
    ap.add_argument("--ports", default="443,80")
    ap.add_argument("--devices", default=None,
                    help="какие устройства использовать, через запятую")
    ap.add_argument("--once", action="store_true",
                    help="обработать одно задание и выйти")
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.adapters:
        return show_adapters(cfg)

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
