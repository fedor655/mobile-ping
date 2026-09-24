# -*- coding: utf-8 -*-
"""
icmp_windows — пинг под Windows через IcmpSendEcho2Ex.

Эта функция выбрана вместо raw-сокета, потому что не требует прав
администратора, и вместо разбора вывода ping.exe, потому что тот локализован.
Исходный адрес задаётся параметром SourceAddress — привязки к интерфейсу
в этом API нет, поэтому маршрут всё равно выбирает ядро (см. probe.icmp_will_leak).

Задержку возвращает сама функция, целыми миллисекундами — отсюда квантование
±0.5 мс, пренебрежимое на фоне дрожания сотовой сети в ±16 мс.
"""

import ctypes
import ctypes.wintypes as wt
import socket
import struct
import time

from consts import SOURCE_INVALID

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
# IP_STATUS, а обычный код Windows. Чаще всего это значит, что исходного
# адреса уже нет на адаптере.
WIN32_STATUS = {
    87: "неверный параметр",
    1214: SOURCE_INVALID,
    1231: "сеть недоступна",
    1232: "узел недоступен",
    10049: SOURCE_INVALID,
    10065: "узел недостижим",
}


def status_text(code):
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


def icmp_ping(dest_ip, src_ip, count=4, timeout_ms=2000, payload=32,
              gap_sec=0.2, if_index=None):
    """
    Пинг с жёстко заданным исходным адресом.

    if_index здесь не используется: у IcmpSendEcho2Ex нет параметра для
    интерфейса. Принимается ради единой сигнатуры с версией под Linux.
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
            if i and gap_sec:
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
                statuses.append(status_text(st))
                if st == 0:
                    rtts.append(float(r.RoundTripTime))
            else:
                statuses.append(status_text(kernel32.GetLastError()))
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
