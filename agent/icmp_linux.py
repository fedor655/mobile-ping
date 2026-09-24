# -*- coding: utf-8 -*-
"""
icmp_linux — пинг под Linux без прав root.

Используется «ping socket»: SOCK_DGRAM с IPPROTO_ICMP. Ядро разрешает его
непривилегированным процессам, если их группа попадает в диапазон
net.ipv4.ping_group_range — на большинстве современных систем он открыт для
всех (`0 2147483647`). Raw-сокет с CAP_NET_RAW не нужен.

Важное отличие от версии под Windows: здесь можно задать не только исходный
адрес, но и сам интерфейс (IP_UNICAST_IF), причём тоже без прав. То есть на
Linux ICMP прибивается к устройству так же жёстко, как TCP, и щель, из-за
которой на Windows приходится отдельно проверять выбор маршрута, здесь
закрыта на уровне сокета.

Задержка меряется таймером процесса, без округления до целых миллисекунд.
"""

import os
import select
import socket
import struct
import time

from consts import SOURCE_INVALID

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
IP_UNICAST_IF = 50          # значение из linux/in.h

ERRNO_TEXT = {
    99: SOURCE_INVALID,          # EADDRNOTAVAIL — адреса нет на интерфейсе
    101: "сеть недоступна",      # ENETUNREACH
    113: "узел недоступен",      # EHOSTUNREACH
    13: "доступ запрещён",       # EACCES
    1: "операция не разрешена",  # EPERM
}


def _checksum(data):
    """Контрольная сумма ICMP. Ядро её пересчитает, но пусть будет верной."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo_packet(ident, seq, payload):
    head = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chk = _checksum(head + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chk, ident, seq) + payload


def icmp_ping(dest_ip, src_ip, count=4, timeout_ms=2000, payload=32,
              gap_sec=0.2, if_index=None):
    """
    Пинг с привязкой к исходному адресу и, если задан, к интерфейсу.

    Возвращает тот же словарь, что и версия под Windows.
    """
    data = b"mobile-ping" + b"." * max(0, payload - 11)
    # Для ping-сокета ядро само подставляет свой идентификатор, поэтому
    # ответы сопоставляем по номеру пакета.
    ident = os.getpid() & 0xFFFF
    timeout = max(0.05, timeout_ms / 1000.0)

    rtts, statuses = [], []
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_ICMP)
        if if_index:
            try:
                sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF,
                                struct.pack("!I", int(if_index)))
            except OSError:
                pass
        if src_ip:
            sock.bind((src_ip, 0))
    except OSError as exc:
        code = exc.errno
        text = ERRNO_TEXT.get(code, "сокет: %s" % (exc.strerror or exc))
        if sock:
            sock.close()
        return {"sent": count, "recv": 0, "rtt_min": None, "rtt_avg": None,
                "rtt_max": None, "status": text, "replies": [text] * count}

    try:
        for seq in range(1, count + 1):
            if seq > 1 and gap_sec:
                time.sleep(gap_sec)
            try:
                t0 = time.perf_counter()
                sock.sendto(_echo_packet(ident, seq, data), (dest_ip, 0))
            except OSError as exc:
                statuses.append(ERRNO_TEXT.get(
                    exc.errno, "отправка: %s" % (exc.strerror or exc)))
                continue

            deadline = t0 + timeout
            got = False
            while True:
                left = deadline - time.perf_counter()
                if left <= 0:
                    break
                ready, _, _ = select.select([sock], [], [], left)
                if not ready:
                    break
                try:
                    packet, addr = sock.recvfrom(2048)
                except OSError:
                    break
                elapsed = (time.perf_counter() - t0) * 1000.0
                # Ping-сокет отдаёт ICMP-заголовок без IP-заголовка.
                if len(packet) < 8:
                    continue
                kind, _, _, _, rseq = struct.unpack("!BBHHH", packet[:8])
                if kind == ICMP_ECHO_REPLY and rseq == seq:
                    rtts.append(elapsed)
                    statuses.append("ok")
                    got = True
                    break
            if not got:
                statuses.append("таймаут")
    finally:
        sock.close()

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
