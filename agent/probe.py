# -*- coding: utf-8 -*-
"""
probe.py — собственно замеры: ICMP, TCP и TLS, всегда с привязкой к нужному
интерфейсу. Часть, общая для Windows и Linux; сам ICMP живёт в icmp_windows.py
и icmp_linux.py.

Главная мысль файла. На машине одновременно живут кабель, Wi-Fi, несколько
телефонов по USB и VPN-туннели. У полнотуннельного VPN маршруты 0.0.0.0/1 и
128.0.0.0/1 перехватывают вообще весь трафик. Поэтому обычный `ping 1.1.1.1`
уходит куда угодно, но не в мобильную сеть нужного телефона. Именно на этом
ломалась первая версия проекта.

Лечение — не правка маршрутов (это роняет сеть целиком), а привязка каждого
замера к устройству:

  * TCP и TLS — сокет с IP_UNICAST_IF, то есть жёстким назначением исходящего
    интерфейса, плюс bind() на его адрес;
  * ICMP под Linux — то же самое, ping-сокет тоже принимает IP_UNICAST_IF;
  * ICMP под Windows — только исходный адрес: у IcmpSendEcho2Ex параметра для
    интерфейса нет. Эта щель закрывается проверкой icmp_will_leak(), которая
    спрашивает у ядра, куда оно отправило бы пакет на самом деле.
"""

import http.client
import json
import ipaddress
import socket
import ssl
import sys
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from consts import SOURCE_INVALID

if sys.platform == "win32":
    from icmp_windows import icmp_ping          # noqa: F401
    # Номер опции «отправлять через этот интерфейс» в Windows.
    IP_UNICAST_IF = 31
    # У IcmpSendEcho2Ex параметра для интерфейса нет — только исходный адрес,
    # поэтому маршрут выбирает ядро и пинги могут уйти мимо устройства.
    ICMP_BOUND_TO_INTERFACE = False
else:
    from icmp_linux import icmp_ping            # noqa: F401
    IP_UNICAST_IF = 50
    # Ping-сокет принимает IP_UNICAST_IF, то есть ICMP прибивается к
    # интерфейсу так же жёстко, как TCP, и щели тут нет.
    ICMP_BOUND_TO_INTERFACE = True

# Порты, на которых осмысленно пробовать TLS-рукопожатие.
TLS_PORTS = (443, 8443, 993, 995, 465)


def _make_tls_context():
    """
    Контекст для рукопожатия, создаётся один раз на процесс.

    Проверка подлинности сертификата выключена намеренно: мы выясняем, дают ли
    нам вообще завершить рукопожатие, а не доверяем ли мы собеседнику. Из-за
    этого не нужно и хранилище сертификатов — а именно его загрузка в
    ssl.create_default_context() стоит 23 мс на вызов под Windows и держит GIL.
    Пока контекст создавался на каждую проверку, TLS упирался в 42 проверки в
    секунду на любом канале.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_TLS_CTX = _make_tls_context()


def bind_to_interface(sock, if_index):
    """
    Жёстко назначить исходящий интерфейс. Индекс — в сетевом порядке байт.

    В отличие от выбора исходного адреса, это не подсказка, а приказ: пакет
    уйдёт через указанный интерфейс мимо обычного выбора маршрута, поэтому
    переживает и полнотуннельный VPN с маршрутами 0.0.0.0/1.
    """
    if not if_index:
        return
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF,
                        struct.pack("!I", int(if_index)))
    except OSError:
        pass          # не поддержано — остаётся привязка по адресу


def route_source_for(dest_ip):
    """
    Какой исходный адрес система выбрала бы для этой цели по своим маршрутам.

    UDP-сокет, подключённый к адресу, не отправляет ни одного пакета, но ядро
    уже выбирает маршрут — и getsockname() отдаёт адрес того интерфейса, через
    который трафик ушёл бы на самом деле.

    Нужно это для ICMP под Windows: там у IcmpSendEcho2Ex есть только исходный
    адрес, привязки к интерфейсу нет, и маршрут всё равно выбирает ядро. Под
    Linux ICMP прибивается к интерфейсу на уровне сокета, но проверка полезна и
    там — как независимое подтверждение.

    Прав не требует и ничего в сеть не посылает.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def icmp_will_leak(src_ip, dest_ip="1.1.1.1"):
    """
    Уйдут ли ICMP мимо нужного интерфейса.

    Возвращает адрес, который выберет ядро, если он отличается от нашего,
    иначе None. Отличие — повод не доверять пингам с этого устройства.

    Там, где ICMP прибивается к интерфейсу на уровне сокета (Linux), выбор
    ядра по маршрутам ни на что не влияет, и проверка всегда возвращает None:
    иначе любое устройство, не являющееся маршрутом по умолчанию, отбраковы-
    валось бы зря — а это как раз обычное положение дел, когда телефонов
    несколько.
    """
    if ICMP_BOUND_TO_INTERFACE:
        return None
    chosen = route_source_for(dest_ip)
    return chosen if (chosen and chosen != src_ip) else None


# Адрес из RFC 5737 (TEST-NET-1): не маршрутизируется нигде в мире. Честный
# путь не может ни установить с ним TCP-соединение, ни получить ответ на ping.
CANARY_IP = "192.0.2.1"


def interception_check(src_ip, if_index=None, timeout=2.0):
    """
    Не подделывает ли кто-то трафик на этом пути.

    Стучимся в адрес, которого не существует. Если TCP «соединился» или ping
    «ответил» — значит, между нами и сетью стоит прокси или VPN в режиме TUN,
    который сам завершает соединения. Так работает, например, sing-box с
    auto_redirect: он перехватывает TCP на уровне netfilter, и никакая
    привязка к интерфейсу, даже IP_UNICAST_IF, его не обходит.

    Через такой путь любой порт выглядит открытым, а любой адрес — живым,
    поэтому замеры с него недействительны целиком. Найдено на боевой машине:
    23 несуществующих адреса из 30 показали «TCP открыт».

    Возвращает None, если всё честно, иначе описание того, что не так.
    """
    def tcp_probe():
        return tcp_check(CANARY_IP, 443, src_ip, timeout=timeout,
                         if_index=if_index)

    def icmp_probe():
        return icmp_ping(CANARY_IP, src_ip, count=1,
                         timeout_ms=int(timeout * 1000), gap_sec=0,
                         if_index=if_index)

    with ThreadPoolExecutor(max_workers=2) as pool:
        t, p = pool.submit(tcp_probe), pool.submit(icmp_probe)
        tcp, ping = t.result(), p.result()

    if tcp.get("ok"):
        return ("TCP-соединение с несуществующим адресом %s установилось за "
                "%.0f мс — TCP на этом пути перехватывает прокси или VPN "
                "(например, sing-box в режиме TUN). Любой порт через него "
                "выглядит открытым." % (CANARY_IP, tcp.get("ms") or 0))
    if ping.get("recv"):
        return ("на ping несуществующего адреса %s пришёл ответ — ICMP на этом "
                "пути подделывает прокси или VPN." % CANARY_IP)
    return None


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


def tcp_check(dest_ip, port, src_ip, timeout=3.0, server_hostname=None,
              if_index=None):
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
        bind_to_interface(s, if_index)
        s.bind((src_ip, 0))
        t0 = time.perf_counter()
        s.connect((dest_ip, port))
        res = {"port": port, "ok": True,
               "ms": (time.perf_counter() - t0) * 1000.0, "error": None}

        if server_hostname and port in TLS_PORTS:
            try:
                with _TLS_CTX.wrap_socket(s,
                                          server_hostname=server_hostname) as tls:
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


def probe_many(targets, src_ip, ports=(443, 80), icmp_count=4,
               icmp_timeout_ms=2000, tcp_timeout=3.0,
               parallel_icmp=500, parallel_tcp=64, if_index=None):
    """
    Замер списка целей в две фазы с разной параллельностью.

    Так сделано не для красоты. ICMP — это одиночные пакеты без состояния,
    мобильный канал держит их тысячами в секунду без потерь. А каждое
    TCP-соединение занимает запись в таблице NAT телефона, и она невелика:
    замер показал, что при 500 одновременных соединениях две трети из них не
    проходят вовсе. С общим лимитом потоков пришлось бы выбирать между
    медленным ICMP и массой ложных «порт закрыт» — поэтому фазы разведены.

    Порядок целей сохраняется.
    """
    def resolve_one(t):
        host, port_in_target = split_target(t)
        out = {"target": t, "resolved_ip": None, "icmp_sent": None,
               "icmp_recv": None, "rtt_min": None, "rtt_avg": None,
               "rtt_max": None, "icmp_status": None, "tcp": [], "error": None}
        try:
            out["resolved_ip"] = resolve(host)
        except OSError as exc:
            out["error"] = "имя не разрешилось: %s" % str(exc)[:60]
        out["_host"] = host
        out["_ports"] = [port_in_target] if port_in_target else list(ports)
        out["_is_name"] = host != out["resolved_ip"]
        return out

    # Имена разрешаем заранее: DNS бывает медленным, и держать под него
    # потоки самого замера незачем.
    with ThreadPoolExecutor(max_workers=max(1, min(64, len(targets)))) as pool:
        results = list(pool.map(resolve_one, targets))

    live = [r for r in results if r["resolved_ip"]]

    def do_icmp(r):
        try:
            got = icmp_ping(r["resolved_ip"], src_ip, count=icmp_count,
                            timeout_ms=icmp_timeout_ms)
            r.update(icmp_sent=got["sent"], icmp_recv=got["recv"],
                     rtt_min=got["rtt_min"], rtt_avg=got["rtt_avg"],
                     rtt_max=got["rtt_max"], icmp_status=got["status"])
        except OSError as exc:
            r["icmp_status"] = "сбой ICMP: %s" % str(exc)[:60]

    def do_tcp(r):
        for port in r["_ports"]:
            r["tcp"].append(tcp_check(
                r["resolved_ip"], port, src_ip, timeout=tcp_timeout,
                server_hostname=r["_host"] if r["_is_name"] else None,
                if_index=if_index))

    if live:
        n = max(1, min(int(parallel_icmp), len(live), 2048))
        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(do_icmp, live))

        n = max(1, min(int(parallel_tcp), len(live), 512))
        with ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(do_tcp, live))

    for r in results:
        r.pop("_host", None)
        r.pop("_ports", None)
        r.pop("_is_name", None)
    return results


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

def _http_get(host, path, src_ip, timeout=8, port=80, if_index=None):
    # src_ip=None — без привязки: так снимается то, что видит маршрут по
    # умолчанию, со всеми прокси и VPN, которые на нём стоят.
    conn = http.client.HTTPConnection(
        host, port, timeout=timeout,
        source_address=(src_ip, 0) if src_ip else None)
    if if_index:
        # HTTPConnection создаёт сокет сам, поэтому подменяем его создателя
        orig = conn._create_connection

        def create(address, timeout=timeout, source_address=None, **kw):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            bind_to_interface(sock, if_index)
            if source_address:
                sock.bind(source_address)
            sock.connect(address)
            return sock

        conn._create_connection = create
    try:
        conn.request("GET", path, headers={"User-Agent": "mobile-ping/1.0",
                                           "Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        return resp.read(4096).decode("utf-8", "replace").strip()
    finally:
        conn.close()


def _operator_of(ip, src_ip, timeout, if_index=None):
    """
    Чей это диапазон. Спрашиваем публичный справочник ip-api.com — он отдаёт
    владельца по базам RIPE, отсюда и «PJSC Vimpelcom · Russia».

    Вызывается отдельно от определения самого адреса: адрес надёжнее взять у
    своего сервера, а название оператора он подсказать не может.
    """
    try:
        body = _http_get("ip-api.com", "/json/%s?fields=country,isp" % ip,
                         src_ip, timeout, if_index=if_index)
        if body:
            d = json.loads(body)
            return " · ".join(x for x in (d.get("isp"), d.get("country")) if x)[:120]
    except (OSError, ValueError):
        pass
    return ""


def egress_info(src_ip, own_server=None, timeout=3, budget=8,
                if_index=None):
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
                             int(port) if port else 80, if_index=if_index)
            if body:
                ip = json.loads(body).get("ip")
                if ip:
                    # адрес уже знаем точно; название оператора — по желанию,
                    # на него тратим не больше пары секунд
                    return {"ip": ip,
                            "info": _operator_of(ip, src_ip, min(3.0, left()),
                                                 if_index)
                                    if left() > 0 else ""}
        except (OSError, ValueError):
            pass

    # 2. ip-api.com — заодно отдаёт оператора, это полезно в отчёте
    if left() > 0:
        try:
            body = _http_get("ip-api.com", "/json/?fields=query,country,isp,as",
                             src_ip, left(), if_index=if_index)
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
            body = _http_get(host, path, src_ip, left(), if_index=if_index)
            if body and len(body) < 60:
                return {"ip": body.strip(), "info": ""}
        except OSError:
            pass
    return {"ip": None, "info": ""}
