# -*- coding: utf-8 -*-
"""
probe.py — собственно замеры: ICMP и TCP, всегда с привязкой к нужному интерфейсу.

Главная мысль файла. На ноутбуке одновременно живут кабель, Wi-Fi и VPN-туннели.
У WireGuard маршруты 0.0.0.0/1 и 128.0.0.0/1 — они перехватывают вообще весь
трафик, а Ethernet имеет метрику лучше, чем Wi-Fi. Поэтому обычный `ping 1.1.1.1`
уходит куда угодно, но не в мобильную сеть телефона. Именно на этом ломалась
прошлая версия.

Лечение — не правка маршрутов (это роняет сеть), а привязка каждого замера к
исходному адресу Wi-Fi-адаптера:
  * ICMP — IcmpSendEcho2Ex, у неё есть параметр SourceAddress;
  * TCP  — обычный сокет с bind((src_ip, 0)) до connect.
Windows использует strong host model, поэтому пакет с исходным адресом Wi-Fi
обязан уйти именно через Wi-Fi.

IcmpSendEcho2Ex выбрана вместо raw-сокета ещё и потому, что не требует прав
администратора, и вместо разбора вывода ping.exe — потому что тот локализован.
"""

import ctypes
import ctypes.wintypes as wt
import http.client
import json
import ipaddress
import socket
import ssl
import struct
import time

iphlpapi = ctypes.WinDLL("iphlpapi.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Коды IP_STATUS из ipexport.h — переводим в человеческие формулировки.
IP_STATUS = {
    0: "ok",
    11001: "буфер мал",
    11002: "сеть недостижима",
    11003: "узел недостижим",
    11004: "протокол недостижим",
    11005: "порт недостижим",
    11006: "нет ресурсов",
    11007: "плохая опция",
    11008: "аппаратная ошибка",
    11009: "пакет слишком велик",
    11010: "таймаут",
    11011: "неверный запрос",
    11012: "нет маршрута",
    11013: "TTL истёк в пути",
    11014: "TTL истёк при сборке",
    11015: "проблема с параметром",
    11016: "source quench",
    11017: "опция слишком велика",
    11018: "неверный адрес назначения",
    11050: "общий сбой",
}

# Когда IcmpSendEcho2Ex не отправила ни одного пакета, GetLastError отдаёт не
# IP_STATUS, а обычный код Windows. Чаще всего это значит, что с указанного
# исходного адреса до цели просто нет маршрута — например, телефон раздаёт
# Wi-Fi, но сам в интернет не выходит.
SOURCE_INVALID = "исходный адрес недоступен"

# Порты, на которых осмысленно пробовать TLS-рукопожатие.
TLS_PORTS = (443, 8443, 993, 995, 465)

WIN32_STATUS = {
    87: "неверный параметр",
    # 1214 приходит, когда исходного адреса уже нет на адаптере: Wi-Fi
    # переподключился и DHCP ещё не выдал новый. Это не «цель недоступна»,
    # а признак того, что замера не было вовсе.
    1214: SOURCE_INVALID,
    1231: "сеть недоступна",
    1232: "узел недоступен",
    10049: SOURCE_INVALID,
    10065: "узел недостижим",
}


def is_public_ip(ip):
    """
    Публичный ли адрес. Нужен для проверки мобильного выхода: если наш внешний
    IP оказался приватным (10.x, 192.168.x, CGNAT 100.64/10), значит запрос
    пришёл на сервер не из интернета, а из туннеля — замер идёт не туда.
    """
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a in ipaddress.ip_network("100.64.0.0/10"):    # CGNAT, тоже не интернет
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_reserved or a.is_multicast)


def source_usable(src_ip):
    """Есть ли сейчас такой адрес на машине и можно ли к нему привязаться."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((src_ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def result_is_invalid(res):
    """Замер не состоялся: исходный адрес пропал, а не цель молчит."""
    if res.get("icmp_status") == SOURCE_INVALID:
        return True
    tcp = res.get("tcp") or []
    return bool(tcp) and all(t.get("error") == SOURCE_INVALID for t in tcp)


def _status_text(code):
    if code in IP_STATUS:
        return IP_STATUS[code]
    if code in WIN32_STATUS:
        return WIN32_STATUS[code]
    return "код %d" % code


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte),
                ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.POINTER(ctypes.c_ubyte))]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", wt.ULONG),
                ("Status", wt.ULONG),
                ("RoundTripTime", wt.ULONG),
                ("DataSize", ctypes.c_ushort),
                ("Reserved", ctypes.c_ushort),
                ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION)]


iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
iphlpapi.IcmpSendEcho2Ex.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    wt.ULONG, wt.ULONG, ctypes.c_void_p, ctypes.c_ushort,
    ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wt.DWORD, wt.DWORD]
iphlpapi.IcmpSendEcho2Ex.restype = wt.DWORD


def _ipaddr(ip_str):
    """'1.2.3.4' -> ULONG в сетевом порядке, как ждёт IPAddr."""
    return struct.unpack("<I", socket.inet_aton(ip_str))[0]


def resolve(host):
    """Имя -> IPv4. Для голого IP возвращает его же."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    return infos[0][4][0]


def split_target(target):
    """'host:port' -> ('host', port); 'host' -> ('host', None)."""
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        if port.isdigit():
            return host, int(port)
    return target, None


def icmp_ping(dest_ip, src_ip, count=4, timeout_ms=2000, payload=32,
              gap_sec=0.2):
    """
    Пинг с жёстко заданным исходным адресом.

    Возвращает dict: sent, recv, rtt_min/avg/max (мс), status (текст последнего
    неуспеха), replies — список статусов по попыткам.
    """
    handle = iphlpapi.IcmpCreateFile()
    if handle == INVALID_HANDLE_VALUE or not handle:
        raise OSError("IcmpCreateFile не удалось")

    data = b"mobile-ping" + b"." * max(0, payload - 11)
    req = ctypes.create_string_buffer(data, len(data))
    reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(data) + 64
    reply = ctypes.create_string_buffer(reply_size)

    src = _ipaddr(src_ip)
    dst = _ipaddr(dest_ip)

    rtts, statuses = [], []
    try:
        for i in range(count):
            if i:
                time.sleep(gap_sec)
            n = iphlpapi.IcmpSendEcho2Ex(
                handle, None, None, None, src, dst,
                ctypes.cast(req, ctypes.c_void_p), ctypes.c_ushort(len(data)),
                None, ctypes.cast(reply, ctypes.c_void_p),
                reply_size, int(timeout_ms))
            if n:
                r = ctypes.cast(reply,
                                ctypes.POINTER(ICMP_ECHO_REPLY)).contents
                st = int(r.Status)
                statuses.append(_status_text(st))
                if st == 0:
                    rtts.append(float(r.RoundTripTime))
            else:
                st = kernel32.GetLastError()
                statuses.append(_status_text(st))
    finally:
        iphlpapi.IcmpCloseHandle(handle)

    bad = [s for s in statuses if s != "ok"]
    return {
        "sent": count,
        "recv": len(rtts),
        "rtt_min": min(rtts) if rtts else None,
        "rtt_avg": sum(rtts) / len(rtts) if rtts else None,
        "rtt_max": max(rtts) if rtts else None,
        "status": (bad[-1] if bad else "ok"),
        "replies": statuses,
    }


def tcp_check(dest_ip, port, src_ip, timeout=3.0, server_hostname=None):
    """
    TCP-рукопожатие с привязкой к src_ip.

    Если задан server_hostname и порт похож на TLS, следом делается настоящее
    TLS-рукопожатие с этим именем в SNI. Без него нельзя ответить на вопрос
    «заблокировано ли»: российский DPI обычно пропускает TCP-соединение и рвёт
    его уже на ClientHello, так что «порт открыт» ничего не доказывает.

    Возвращает dict(port, ok, ms, error, tls, tls_error).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.bind((src_ip, 0))
        t0 = time.perf_counter()
        s.connect((dest_ip, port))
        res = {"port": port, "ok": True,
               "ms": (time.perf_counter() - t0) * 1000.0, "error": None}

        if server_hostname and port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False          # проверяем доступность, не доверие
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with ctx.wrap_socket(s, server_hostname=server_hostname) as tls:
                    res["tls"] = True
                    res["tls_proto"] = tls.version()
            except ssl.SSLError as exc:
                res["tls"] = False
                res["tls_error"] = ("TLS отвергнут: %s"
                                    % str(exc.reason or exc)[:60])
            except socket.timeout:
                res["tls"] = False
                res["tls_error"] = "TLS без ответа (молча режут)"
            except OSError as exc:
                code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                res["tls"] = False
                res["tls_error"] = ("TLS сброшен" if code == 10054
                                    else "TLS: %s" % str(exc)[:50])
        return res
    except socket.timeout:
        return {"port": port, "ok": False, "ms": None, "error": "таймаут"}
    except OSError as exc:
        msg = getattr(exc, "strerror", None) or str(exc)
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        short = {10061: "соединение отклонено",
                 10060: "таймаут",
                 10065: "узел недостижим",
                 10051: "сеть недостижима",
                 10049: SOURCE_INVALID,
                 10013: "доступ запрещён"}.get(code, msg)
        return {"port": port, "ok": False, "ms": None, "error": str(short)[:80]}
    finally:
        s.close()


def probe_target(target, src_ip, ports=(443, 80), icmp_count=4,
                 icmp_timeout_ms=2000, tcp_timeout=3.0):
    """Полный замер одной цели: разрешение имени + ICMP + TCP по портам."""
    host, port_in_target = split_target(target)
    out = {"target": target, "resolved_ip": None, "icmp_sent": None,
           "icmp_recv": None, "rtt_min": None, "rtt_avg": None,
           "rtt_max": None, "icmp_status": None, "tcp": [], "error": None}
    try:
        ip = resolve(host)
    except OSError as exc:
        out["error"] = "имя не разрешилось: %s" % str(exc)[:60]
        return out
    out["resolved_ip"] = ip

    try:
        r = icmp_ping(ip, src_ip, count=icmp_count, timeout_ms=icmp_timeout_ms)
        out.update(icmp_sent=r["sent"], icmp_recv=r["recv"],
                   rtt_min=r["rtt_min"], rtt_avg=r["rtt_avg"],
                   rtt_max=r["rtt_max"], icmp_status=r["status"])
    except OSError as exc:
        out["icmp_status"] = "сбой ICMP: %s" % str(exc)[:60]

    check_ports = [port_in_target] if port_in_target else list(ports)
    is_name = host != ip                       # SNI имеет смысл только для имени
    for p in check_ports:
        out["tcp"].append(tcp_check(ip, p, src_ip, timeout=tcp_timeout,
                                    server_hostname=host if is_name else None))
    return out


# --------------------------------------------------------------------------
# определение внешнего IP через конкретный интерфейс
# --------------------------------------------------------------------------

def _http_get(host, path, src_ip, timeout=8, port=80):
    conn = http.client.HTTPConnection(host, port, timeout=timeout,
                                      source_address=(src_ip, 0))
    try:
        conn.request("GET", path, headers={"User-Agent": "mobile-ping/1.0",
                                           "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        return resp.read(4096).decode("utf-8", "replace").strip()
    finally:
        conn.close()


def _operator_of(ip, src_ip, timeout):
    """
    Чей это диапазон. Спрашиваем публичный справочник ip-api.com — он отдаёт
    владельца по базам RIPE, отсюда и «PJSC Vimpelcom · Russia».

    Вызывается отдельно от определения самого адреса: адрес надёжнее взять у
    своего сервера, а название оператора он подсказать не может.
    """
    try:
        body = _http_get("ip-api.com", "/json/%s?fields=country,isp" % ip,
                         src_ip, timeout)
        if body:
            d = json.loads(body)
            return " · ".join(x for x in (d.get("isp"), d.get("country")) if x)[:120]
    except (OSError, ValueError):
        pass
    return ""


def egress_info(src_ip, own_server=None, timeout=3, budget=8):
    """
    Узнать, с какого внешнего адреса виден трафик, уходящий с src_ip.

    Сначала спрашиваем свой сервер (не зависим от чужих сервисов), затем
    публичные echo-сервисы. `budget` ограничивает суммарное время: если за
    точкой доступа интернета нет вообще, перебирать все запасные варианты
    бессмысленно — это втрое удлиняет обход телефонов.

    Возвращает dict(ip, info) или dict(ip=None, info="").
    """
    deadline = time.time() + budget

    def left():
        return min(timeout, deadline - time.time())

    # 1. собственный сервер
    if own_server and left() > 0:
        try:
            host, _, port = own_server.partition(":")
            body = _http_get(host, "/api/whoami", src_ip, left(),
                             int(port) if port else 80)
            if body:
                ip = json.loads(body).get("ip")
                if ip:
                    # адрес уже знаем точно; название оператора — по желанию,
                    # на него тратим не больше пары секунд
                    return {"ip": ip,
                            "info": _operator_of(ip, src_ip, min(3.0, left()))
                                    if left() > 0 else ""}
        except (OSError, ValueError):
            pass

    # 2. ip-api.com — заодно отдаёт оператора, это полезно в отчёте
    if left() > 0:
        try:
            body = _http_get("ip-api.com", "/json/?fields=query,country,isp,as",
                             src_ip, left())
            if body:
                d = json.loads(body)
                if d.get("query"):
                    info = " · ".join(x for x in (d.get("isp"), d.get("country"))
                                      if x)
                    return {"ip": d["query"], "info": info[:120]}
        except (OSError, ValueError):
            pass

    # 3. самые простые запасные варианты
    for host, path in (("ifconfig.me", "/ip"), ("api.ipify.org", "/")):
        if left() <= 0:
            break
        try:
            body = _http_get(host, path, src_ip, left())
            if body and len(body) < 60:
                return {"ip": body.strip(), "info": ""}
        except OSError:
            pass
    return {"ip": None, "info": ""}
