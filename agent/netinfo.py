# -*- coding: utf-8 -*-
"""
netinfo.py — сведения об адаптерах Windows через GetAdaptersAddresses.

Почему не парсим `ipconfig`: его вывод локализован, на русской Windows ключи
переведены и любой парсер ломается. Вызов Win32 API возвращает те же данные
структурой и от языка системы не зависит.
"""

import ctypes
import ctypes.wintypes as wt
import socket

iphlpapi = ctypes.WinDLL("iphlpapi.dll")

AF_UNSPEC, AF_INET, AF_INET6 = 0, 2, 23

GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080

ERROR_BUFFER_OVERFLOW = 111
IF_TYPE_IEEE80211 = 71
IF_TYPE_ETHERNET = 6
IF_OPER_STATUS_UP = 1

MAX_ADAPTER_ADDRESS_LENGTH = 8


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p),
                ("iSockaddrLength", ctypes.c_int)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wt.ULONG),
    ("Flags", wt.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", wt.ULONG),
    ("PreferredLifetime", wt.ULONG),
    ("LeaseLifetime", wt.ULONG),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ("Length", wt.ULONG),
    ("Reserved", wt.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wt.ULONG),
    ("IfIndex", wt.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", wt.ULONG),
    ("Flags", wt.ULONG),
    ("Mtu", wt.ULONG),
    ("IfType", wt.DWORD),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", wt.DWORD),
    ("ZoneIndices", wt.ULONG * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_ulonglong),
    ("ReceiveLinkSpeed", ctypes.c_ulonglong),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", wt.ULONG),
    ("Ipv6Metric", wt.ULONG),
    ("Luid", ctypes.c_ulonglong),
    ("Dhcpv4Server", SOCKET_ADDRESS),
    ("CompartmentId", wt.DWORD),
    ("NetworkGuid", ctypes.c_ubyte * 16),
    ("ConnectionType", ctypes.c_int),
    ("TunnelType", ctypes.c_int),
    ("Dhcpv6Server", SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid", ctypes.c_ubyte * 130),
    ("Dhcpv6ClientDuidLength", wt.ULONG),
    ("Dhcpv6Iaid", wt.ULONG),
    ("FirstDnsSuffix", ctypes.c_void_p),
]


def _sockaddr_to_str(sa):
    """SOCKET_ADDRESS -> строка с IP-адресом (или None)."""
    if not sa.lpSockaddr or sa.iSockaddrLength <= 0:
        return None
    raw = ctypes.string_at(sa.lpSockaddr, sa.iSockaddrLength)
    family = int.from_bytes(raw[0:2], "little")
    try:
        if family == AF_INET and len(raw) >= 8:
            return socket.inet_ntop(socket.AF_INET, raw[4:8])
        if family == AF_INET6 and len(raw) >= 24:
            return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    except OSError:
        return None
    return None


def adapters():
    """Список адаптеров: dict(index, name, description, type, up, ipv4, gateways, metric)."""
    flags = (GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
             GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS)
    size = wt.ULONG(15 * 1024)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        rc = iphlpapi.GetAdaptersAddresses(
            wt.ULONG(AF_UNSPEC), wt.ULONG(flags), None,
            ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
            ctypes.byref(size))
        if rc == ERROR_BUFFER_OVERFLOW:
            continue
        if rc != 0:
            raise OSError("GetAdaptersAddresses вернул %d" % rc)
        break
    else:
        raise OSError("GetAdaptersAddresses: буфер не подошёл")

    out = []
    node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while node:
        a = node.contents
        ipv4, ipv6 = [], []
        ua = a.FirstUnicastAddress
        while ua:
            ip = _sockaddr_to_str(ua.contents.Address)
            if ip:
                (ipv6 if ":" in ip else ipv4).append(ip)
            ua = ua.contents.Next
        gws = []
        ga = a.FirstGatewayAddress
        while ga:
            ip = _sockaddr_to_str(ga.contents.Address)
            if ip and ":" not in ip:
                gws.append(ip)
            ga = ga.contents.Next
        out.append({
            "index": int(a.IfIndex),
            "name": a.FriendlyName or "",
            "description": a.Description or "",
            "type": int(a.IfType),
            "up": int(a.OperStatus) == IF_OPER_STATUS_UP,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gateways": gws,
            "metric": int(a.Ipv4Metric),
            "mac": ":".join("%02x" % b for b in
                            a.PhysicalAddress[:a.PhysicalAddressLength]),
        })
        node = a.Next
    return out


def wifi_adapter(prefer_name=None):
    """Найти Wi-Fi адаптер. prefer_name — точное имя ('Беспроводная сеть')."""
    ads = adapters()
    if prefer_name:
        for a in ads:
            if a["name"] == prefer_name:
                return a
        raise LookupError("адаптер %r не найден; есть: %s"
                          % (prefer_name, ", ".join(x["name"] for x in ads)))
    wifi = [a for a in ads if a["type"] == IF_TYPE_IEEE80211]
    if not wifi:
        raise LookupError("Wi-Fi адаптер не найден")
    wifi.sort(key=lambda a: (not a["up"], not a["ipv4"]))
    return wifi[0]


def by_index(index):
    for a in adapters():
        if a["index"] == index:
            return a
    return None


def capturing_tunnels():
    """
    Туннели, которые перехватят трафик раньше, чем сработает привязка к адресу
    Wi-Fi.

    Полнотуннельные VPN ставят маршруты 0.0.0.0/1 и 128.0.0.0/1: они длиннее
    обычного 0.0.0.0/0 и потому выигрывают выбор маршрута. Привязка сокета к
    исходному адресу такой перехват не отменяет, и замер молча уходит через
    VPN — сайт, заблокированный у оператора, выглядит доступным.

    Признак ищем по адресу интерфейса: у WireGuard/AmneziaWG это отдельная
    подсеть туннеля, а не адрес локальной сети.
    """
    out = []
    for a in adapters():
        if not (a["up"] and a["ipv4"]):
            continue
        blob = (a["description"] + " " + a["name"]).lower()
        if any(m in blob for m in ("wireguard", "wintun", "tap-windows",
                                   "openvpn", "amnezia")):
            out.append(a)
    return out


def routing_tunnels():
    """
    Интерфейсы-туннели, которые могут перехватывать трафик (WireGuard, OpenVPN,
    Tailscale и подобные). Нужны, чтобы честно предупредить: замер может уйти
    не туда, куда мы думаем.
    """
    marks = ("wireguard", "wintun", "tap-windows", "openvpn", "tailscale",
             "tunnel", "radmin")
    out = []
    for a in adapters():
        if not a["up"] or not a["ipv4"]:
            continue
        blob = (a["description"] + " " + a["name"]).lower()
        if any(m in blob for m in marks):
            out.append(a)
    return out


if __name__ == "__main__":
    for a in adapters():
        if a["up"]:
            print("%-32s idx=%-4d type=%-3d metric=%-5d ipv4=%s gw=%s"
                  % (a["name"][:32], a["index"], a["type"], a["metric"],
                     ",".join(a["ipv4"]) or "-", ",".join(a["gateways"]) or "-"))
