# -*- coding: utf-8 -*-
"""
netinfo_linux — сведения об интерфейсах под Linux.

Источники данных выбраны так, чтобы не зависеть от языка системы и не
требовать прав: iproute2 умеет отдавать JSON (`ip -j`), а драйвер устройства
виден в /sys. Разбирать человекочитаемый вывод `ifconfig`/`ip addr` не нужно.

Наружу отдаём те же словари, что и версия под Windows, поэтому остальной агент
одинаков на обеих системах. Поле `description` здесь — имя драйвера
(`rndis_host`, `cdc_ncm`, `r8169`): именно по нему опознаются телефоны,
подключённые кабелем.
"""

import json
import os
import socket
import subprocess

# Драйверы, которыми телефон отдаёт интернет по USB.
USB_TETHER_DRIVERS = {
    "rndis_host",     # Android, классический режим модема
    "cdc_ncm",        # Android поновее
    "cdc_ether",
    "cdc_mbim",
    "ipheth",         # iPhone
    "rndis_wlan",
}

# Интерфейсы, через которые трафик может уйти мимо выбранного устройства.
TUNNEL_KINDS = {"tun", "tap", "wireguard", "ppp", "vti", "ipip", "gre"}


def _ip_json(args):
    try:
        out = subprocess.run(["ip", "-j"] + args, capture_output=True,
                             text=True, timeout=10)
        return json.loads(out.stdout or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def _driver_of(name):
    """Имя драйвера устройства, если оно физическое."""
    link = "/sys/class/net/%s/device/driver" % name
    # realpath несуществующего пути возвращает сам путь, поэтому без проверки
    # у виртуальных интерфейсов «драйвером» оказывалось слово driver.
    if not os.path.islink(link):
        return ""
    try:
        return os.path.basename(os.path.realpath(link))
    except OSError:
        return ""


def _kind_of(name, raw):
    """Тип виртуального интерфейса: tun, wireguard и прочее."""
    kind = (raw.get("linkinfo") or {}).get("info_kind") or ""
    if kind:
        return kind
    if os.path.isdir("/sys/class/net/%s/tun_flags" % name) or \
            os.path.exists("/sys/class/net/%s/tun_flags" % name):
        return "tun"
    return ""


def _is_wireless(name):
    return os.path.isdir("/sys/class/net/%s/wireless" % name) or \
        os.path.islink("/sys/class/net/%s/phy80211" % name)


def adapters():
    """
    Список интерфейсов в том же виде, что и под Windows.

    type: 71 — беспроводной, 6 — всё остальное. Числа взяты из Windows,
    чтобы вызывающий код не различал платформы.
    """
    addrs = _ip_json(["addr", "show"])
    routes = _ip_json(["route", "show"])

    # Шлюз и метрика берутся из маршрутов по умолчанию этого интерфейса.
    gateways, metrics = {}, {}
    for r in routes:
        dev = r.get("dev")
        if not dev:
            continue
        if r.get("dst") in ("default", "0.0.0.0/0"):
            if r.get("gateway"):
                gateways.setdefault(dev, []).append(r["gateway"])
            if r.get("metric") is not None:
                metrics.setdefault(dev, r["metric"])

    out = []
    for a in addrs:
        name = a.get("ifname") or ""
        if not name:
            continue
        ipv4 = [x["local"] for x in a.get("addr_info", [])
                if x.get("family") == "inet" and x.get("local")]
        ipv6 = [x["local"] for x in a.get("addr_info", [])
                if x.get("family") == "inet6" and x.get("local")]
        driver = _driver_of(name)
        kind = _kind_of(name, a)
        out.append({
            "index": a.get("ifindex") or 0,
            "name": name,
            # описание — то, по чему опознают устройство: драйвер или тип
            "description": driver or kind or name,
            "driver": driver,
            "kind": kind,
            "type": 71 if _is_wireless(name) else 6,
            "up": a.get("operstate") in ("UP", "UNKNOWN"),
            "ipv4": ipv4,
            "ipv6": ipv6,
            "gateways": gateways.get(name, []),
            "metric": metrics.get(name, 0),
            "mac": a.get("address") or "",
        })
    return out


def by_index(index):
    for a in adapters():
        if a["index"] == index:
            return a
    return None


def wifi_adapter(prefer_name=None):
    ads = adapters()
    if prefer_name:
        for a in ads:
            if a["name"] == prefer_name:
                return a
        raise LookupError("интерфейс %r не найден; есть: %s"
                          % (prefer_name, ", ".join(x["name"] for x in ads)))
    wifi = [a for a in ads if a["type"] == 71]
    if not wifi:
        raise LookupError("беспроводной интерфейс не найден")
    wifi.sort(key=lambda a: (not a["up"], not a["ipv4"]))
    return wifi[0]


def _norm_mac(s):
    return "".join(c for c in (s or "").lower() if c in "0123456789abcdef")


def match_adapters(pattern):
    """
    Подходящие интерфейсы, от точного совпадения к нестрогому.

    Годится имя (`enp5s0f4u1u4`), MAC или подстрока имени либо драйвера.
    Возвращается список: про неоднозначность честнее сказать вслух, чем молча
    взять первый попавшийся и мерить не тот телефон.
    """
    if not pattern:
        return []
    ads = adapters()

    exact = [a for a in ads if a["name"] == pattern]
    if exact:
        return exact

    mac = _norm_mac(pattern)
    if len(mac) == 12:
        by_mac = [a for a in ads if _norm_mac(a["mac"]) == mac]
        if by_mac:
            return by_mac

    low = pattern.lower()
    return [a for a in ads
            if low in a["name"].lower() or low in a["description"].lower()]


def find_adapter(pattern):
    found = match_adapters(pattern)
    return found[0] if len(found) == 1 else None


def usable_ipv4(adapter):
    """Рабочий адрес: без link-local 169.254.x, которого сеть не знает."""
    for ip in (adapter or {}).get("ipv4", []):
        if not ip.startswith("169.254."):
            return ip
    return None


def usb_tethering_adapters():
    """Телефоны, отдающие интернет по кабелю, — опознаются по драйверу."""
    return [a for a in adapters()
            if a["driver"] in USB_TETHER_DRIVERS and a["up"]]


def capturing_tunnels():
    """
    Туннели, которые перехватят трафик раньше привязки к интерфейсу.

    Признак — маршрут по умолчанию или половинки 0.0.0.0/1 и 128.0.0.0/1,
    которыми полнотуннельные VPN перебивают обычный default.
    """
    grabbing = set()
    for r in _ip_json(["route", "show"]):
        if r.get("dst") in ("default", "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"):
            if r.get("dev"):
                grabbing.add(r["dev"])

    out = []
    for a in adapters():
        if not (a["up"] and a["ipv4"]):
            continue
        if a["kind"] in TUNNEL_KINDS and a["name"] in grabbing:
            out.append(a)
    return out


def routing_tunnels():
    """Все поднятые туннели, даже если маршрут по умолчанию не их."""
    return [a for a in adapters()
            if a["up"] and a["ipv4"] and a["kind"] in TUNNEL_KINDS]
