# -*- coding: utf-8 -*-
"""
wifi_windows.py — подключение к точкам доступа и опрос текущего состояния.

Состояние читаем через WlanQueryInterface, а не разбором `netsh wlan show
interfaces`: вывод netsh отдаётся в OEM-кодировке и локализован, а SSID у нас
бывает кириллический (точка называется «сеть»). API отдаёт сырые байты SSID,
которые мы декодируем как UTF-8 — ровно так, как их передаёт точка доступа.

Само подключение делает netsh: у него есть готовый импорт профиля XML.
"""

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import tempfile
import time
from xml.sax.saxutils import escape

wlanapi = ctypes.WinDLL("wlanapi.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")

WLAN_MAX_NAME_LENGTH = 256
DOT11_SSID_MAX_LENGTH = 32
WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7

INTERFACE_STATE = {
    0: "not_ready", 1: "connected", 2: "ad_hoc", 3: "disconnecting",
    4: "disconnected", 5: "associating", 6: "discovering", 7: "authenticating",
}


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", GUID),
                ("strInterfaceDescription", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("isState", ctypes.c_uint)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wt.DWORD), ("dwIndex", wt.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_ulong),
                ("ucSSID", ctypes.c_ubyte * DOT11_SSID_MAX_LENGTH)]


class WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("dot11BssType", ctypes.c_uint),
                ("dot11Bssid", ctypes.c_ubyte * 6),
                ("dot11PhyType", ctypes.c_uint),
                ("uDot11PhyIndex", ctypes.c_ulong),
                ("wlanSignalQuality", ctypes.c_ulong),
                ("ulRxRate", ctypes.c_ulong),
                ("ulTxRate", ctypes.c_ulong)]


class WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("bSecurityEnabled", ctypes.c_int),
                ("bOneXEnabled", ctypes.c_int),
                ("dot11AuthAlgorithm", ctypes.c_uint),
                ("dot11CipherAlgorithm", ctypes.c_uint)]


class WLAN_AVAILABLE_NETWORK(ctypes.Structure):
    _fields_ = [("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("dot11Ssid", DOT11_SSID),
                ("dot11BssType", ctypes.c_uint),
                ("uNumberOfBssids", ctypes.c_ulong),
                ("bNetworkConnectable", ctypes.c_int),
                ("wlanNotConnectableReason", ctypes.c_ulong),
                ("uNumberOfPhyTypes", ctypes.c_ulong),
                ("dot11PhyTypes", ctypes.c_uint * 8),
                ("bMorePhyTypes", ctypes.c_int),
                ("wlanSignalQuality", ctypes.c_ulong),
                ("bSecurityEnabled", ctypes.c_int),
                ("dot11DefaultAuthAlgorithm", ctypes.c_uint),
                ("dot11DefaultCipherAlgorithm", ctypes.c_uint),
                ("dwFlags", wt.DWORD),
                ("dwReserved", wt.DWORD)]


class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wt.DWORD), ("dwIndex", wt.DWORD),
                ("Network", WLAN_AVAILABLE_NETWORK * 1)]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("isState", ctypes.c_uint),
                ("wlanConnectionMode", ctypes.c_uint),
                ("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
                ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]


class WlanError(OSError):
    pass


def _check(rc, what):
    if rc != 0:
        raise WlanError("%s: код %d" % (what, rc))


class _Wlan:
    """Обёртка над дескриптором WLAN — открывается и закрывается по месту."""

    def __enter__(self):
        self.handle = wt.HANDLE()
        negotiated = wt.DWORD()
        _check(wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated),
                                      ctypes.byref(self.handle)),
               "WlanOpenHandle")
        return self

    def __exit__(self, *exc):
        wlanapi.WlanCloseHandle(self.handle, None)
        return False

    def interfaces(self):
        ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        _check(wlanapi.WlanEnumInterfaces(self.handle, None, ctypes.byref(ptr)),
               "WlanEnumInterfaces")
        try:
            lst = ptr.contents
            arr = ctypes.cast(
                ctypes.byref(lst.InterfaceInfo),
                ctypes.POINTER(WLAN_INTERFACE_INFO * lst.dwNumberOfItems)).contents
            return [{"guid": GUID.from_buffer_copy(i.InterfaceGuid),
                     "description": i.strInterfaceDescription,
                     "state": INTERFACE_STATE.get(i.isState, str(i.isState))}
                    for i in arr]
        finally:
            wlanapi.WlanFreeMemory(ptr)

    def scan(self, guid, wait=4.0):
        """Попросить адаптер обновить список сетей и подождать результат."""
        wlanapi.WlanScan(self.handle, ctypes.byref(guid), None, None, None)
        time.sleep(wait)

    def available(self, guid):
        """Видимые сети. SSID берём сырыми байтами — кириллица не ломается."""
        ptr = ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST)()
        rc = wlanapi.WlanGetAvailableNetworkList(
            self.handle, ctypes.byref(guid), 3, None, ctypes.byref(ptr))
        if rc != 0:
            return []
        try:
            lst = ptr.contents
            arr = ctypes.cast(
                ctypes.byref(lst.Network),
                ctypes.POINTER(WLAN_AVAILABLE_NETWORK * lst.dwNumberOfItems)
            ).contents
            seen, out = set(), []
            for n in arr:
                raw = bytes(n.dot11Ssid.ucSSID[:n.dot11Ssid.uSSIDLength])
                ssid = raw.decode("utf-8", "replace")
                key = (ssid, n.strProfileName)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"ssid": ssid, "ssid_raw": raw,
                            "profile": n.strProfileName,
                            "signal": int(n.wlanSignalQuality),
                            "secure": bool(n.bSecurityEnabled),
                            "connectable": bool(n.bNetworkConnectable)})
            out.sort(key=lambda x: -x["signal"])
            return out
        finally:
            wlanapi.WlanFreeMemory(ptr)

    def connection(self, guid):
        size = wt.DWORD()
        data = ctypes.c_void_p()
        rc = wlanapi.WlanQueryInterface(
            self.handle, ctypes.byref(guid),
            WLAN_INTF_OPCODE_CURRENT_CONNECTION, None,
            ctypes.byref(size), ctypes.byref(data), None)
        if rc != 0:                       # 1168 = не подключено, это не ошибка
            return None
        try:
            attrs = ctypes.cast(
                data, ctypes.POINTER(WLAN_CONNECTION_ATTRIBUTES)).contents
            a = attrs.wlanAssociationAttributes
            raw = bytes(a.dot11Ssid.ucSSID[:a.dot11Ssid.uSSIDLength])
            return {
                "state": INTERFACE_STATE.get(attrs.isState, str(attrs.isState)),
                "profile": attrs.strProfileName,
                "ssid": raw.decode("utf-8", "replace"),
                "ssid_raw": raw,
                "bssid": ":".join("%02x" % b for b in a.dot11Bssid),
                "signal": int(a.wlanSignalQuality),
                "rx_kbps": int(a.ulRxRate),
                "tx_kbps": int(a.ulTxRate),
            }
        finally:
            wlanapi.WlanFreeMemory(data)


def _pick_interface(w, description_contains=None):
    ifaces = w.interfaces()
    if description_contains:
        ifaces = [i for i in ifaces
                  if description_contains.lower() in i["description"].lower()] \
                 or ifaces
    if not ifaces:
        raise WlanError("Wi-Fi адаптеров в системе нет")
    return ifaces[0]


def scan(description_contains=None, rescan=True):
    """Список видимых сетей, по убыванию сигнала."""
    with _Wlan() as w:
        iface = _pick_interface(w, description_contains)
        if rescan:
            w.scan(iface["guid"])
        return w.available(iface["guid"])


def current(description_contains=None):
    """
    Текущее подключение Wi-Fi.

    description_contains — часть описания адаптера ('Intel(R) Wi-Fi 6 AX200'),
    если адаптеров несколько. Возвращает dict или None.
    """
    with _Wlan() as w:
        ifaces = w.interfaces()
        if description_contains:
            ifaces = [i for i in ifaces
                      if description_contains.lower() in i["description"].lower()] \
                     or ifaces
        for i in ifaces:
            conn = w.connection(i["guid"])
            if conn and conn["state"] == "connected":
                conn["interface_description"] = i["description"]
                return conn
        if ifaces:
            return {"state": ifaces[0]["state"], "ssid": None, "profile": None,
                    "bssid": None, "signal": 0,
                    "interface_description": ifaces[0]["description"]}
    return None


# --------------------------------------------------------------------------
# профили и подключение (через netsh)
# --------------------------------------------------------------------------

def _decode(raw):
    """Вывод netsh приходит в OEM-кодировке консоли."""
    cps = ["utf-8"]
    try:
        cp = kernel32.GetConsoleOutputCP() or kernel32.GetOEMCP()
        cps.append("cp%d" % cp)
    except Exception:
        pass
    cps += ["cp866", "cp1251"]
    for cp in cps:
        try:
            return raw.decode(cp)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _netsh(args, timeout=45):
    p = subprocess.run(["netsh"] + args, capture_output=True, timeout=timeout,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.returncode, _decode(p.stdout or b"") + _decode(p.stderr or b"")


PROFILE_TEMPLATE = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{name}</name>
  <SSIDConfig>
    <SSID>
      <hex>{hex}</hex>
      <name>{ssid}</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>{mode}</connectionMode>
  <MSM>
    <security>
{security}
    </security>
  </MSM>
</WLANProfile>
"""

SECURITY_PSK = """      <authEncryption>
        <authentication>{auth}</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{key}</keyMaterial>
      </sharedKey>"""

# Порядок попыток для закрытой сети. Точка доступа телефона может быть поднята
# и как WPA2-PSK, и как WPA3-SAE (Android 13+ нередко по умолчанию делает
# смешанный или чистый WPA3). Профиль с неподходящим типом не подключится, а
# Windows после неудачи уводит адаптер в любую другую знакомую сеть — именно
# так замеры и уезжали не туда.
AUTH_VARIANTS = ("WPA2PSK", "WPA3SAE")

SECURITY_OPEN = """      <authEncryption>
        <authentication>open</authentication>
        <encryption>none</encryption>
        <useOneX>false</useOneX>
      </authEncryption>"""


def ensure_profile(ssid, password=None, profile_name=None, auth="WPA2PSK",
                   auto=False):
    """
    Создать/обновить профиль сети.

    auto=False (по умолчанию) — connectionMode manual: Windows не должна сама
    цепляться к точкам телефонов, подключением управляет только агент.
    Для обычной домашней сети наоборот нужен auto, иначе после перезагрузки
    машина останется без связи.
    """
    name = profile_name or ssid
    sec = (SECURITY_PSK.format(auth=auth, key=escape(password)) if password
           else SECURITY_OPEN)
    xml = PROFILE_TEMPLATE.format(
        name=escape(name), ssid=escape(ssid),
        hex=ssid.encode("utf-8").hex().upper(), security=sec,
        mode="auto" if auto else "manual")

    fd, path = tempfile.mkstemp(suffix=".xml", prefix="mobile-ping-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(xml)
        rc, out = _netsh(["wlan", "add", "profile",
                          "filename=%s" % path, "user=current"])
        if rc != 0:
            rc, out = _netsh(["wlan", "add", "profile", "filename=%s" % path])
        if rc != 0:
            raise WlanError("не удалось добавить профиль %r: %s"
                            % (name, out.strip()[:160]))
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return name


def connect(ssid, interface_name, profile_name=None, timeout=45,
            description_contains=None, attempts=3):
    """
    Подключиться к SSID и дождаться реального состояния connected.

    Параметр `ssid=` команде netsh не передаётся намеренно: Windows кодирует
    его не в UTF-8, и для кириллического имени («сеть») возникает расхождение с
    профилем — netsh отвечает «SSID отсутствует в профиле». Сеть однозначно
    задаётся самим профилем.

    Попытка не одна, потому что после неудачной ассоциации Windows своим
    автоподключением уводит адаптер в любую другую знакомую сеть; повторная
    команда перебивает это.
    """
    name = profile_name or ssid
    deadline = time.time() + timeout
    last = None
    for attempt in range(attempts):
        rc, out = _netsh(["wlan", "connect", "name=%s" % name,
                          "interface=%s" % interface_name])
        if rc != 0:
            raise WlanError("netsh wlan connect: %s" % out.strip()[:200])

        slice_end = min(deadline, time.time() + max(8.0, timeout / attempts))
        while time.time() < slice_end:
            time.sleep(1.0)
            last = current(description_contains)
            if last and last.get("state") == "connected" \
                    and last.get("ssid") == ssid:
                return last
        if time.time() >= deadline:
            break

    where = (last or {}).get("ssid") or (last or {}).get("state") or "неизвестно"
    raise WlanError("не подключились к %r за %d с (адаптер сейчас: %s)"
                    % (ssid, timeout, where))


def join(ssid, interface_name, password=None, is_open=False, timeout=45,
         description_contains=None, auto=False):
    """
    Подключиться к сети, сам разобравшись с типом защиты.

    password и is_open не заданы -> сеть уже заведена в Windows, её профиль
    не трогаем. Иначе перебираем типы аутентификации, пока один не сработает.
    """
    if not password and not is_open:
        return connect(ssid, interface_name, timeout=timeout,
                       description_contains=description_contains)

    if is_open or not password:
        ensure_profile(ssid, None, auto=auto)
        return connect(ssid, interface_name, timeout=timeout,
                       description_contains=description_contains)

    errors = []
    for auth in AUTH_VARIANTS:
        ensure_profile(ssid, password, auth=auth, auto=auto)
        try:
            return connect(ssid, interface_name, timeout=timeout,
                           description_contains=description_contains,
                           attempts=2)
        except WlanError as exc:
            errors.append("%s: %s" % (auth, exc))
    raise WlanError("; ".join(errors))


def disconnect(interface_name):
    _netsh(["wlan", "disconnect", "interface=%s" % interface_name])


def delete_profile(profile_name):
    _netsh(["wlan", "delete", "profile", "name=%s" % profile_name])


def wait_for_ip(adapter_index, timeout=30, exclude_ip=None):
    """
    Дождаться, пока адаптер получит рабочий IPv4 и шлюз.

    exclude_ip — адрес, который был до переключения: пока он не сменился,
    считаем, что DHCP ещё не отработал.
    """
    import netinfo
    deadline = time.time() + timeout
    while time.time() < deadline:
        a = netinfo.by_index(adapter_index)
        if a and a["ipv4"] and a["gateways"]:
            ip = a["ipv4"][0]
            if not ip.startswith("169.254.") and ip != exclude_ip:
                return a
        time.sleep(1.0)
    raise WlanError("адаптер не получил адрес за %d с" % timeout)


if __name__ == "__main__":
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")
    with _Wlan() as w:
        for i in w.interfaces():
            print("адаптер:", i["description"], "|", i["state"])
    print("сейчас:", current())
