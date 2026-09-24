# -*- coding: utf-8 -*-
"""
netinfo — сведения о сетевых интерфейсах, единый вид на обеих системах.

Реализации разные: под Windows это вызовы GetAdaptersAddresses, под Linux
разбор JSON от iproute2 и /sys. Наружу обе отдают одинаковые словари, поэтому
остальной агент о платформе не знает.
"""

import sys

if sys.platform == "win32":
    from netinfo_windows import (           # noqa: F401
        adapters, wifi_adapter, by_index, find_adapter, match_adapters,
        usable_ipv4, usb_tethering_adapters, capturing_tunnels,
        routing_tunnels,
    )
else:
    from netinfo_linux import (             # noqa: F401
        adapters, wifi_adapter, by_index, find_adapter, match_adapters,
        usable_ipv4, usb_tethering_adapters, capturing_tunnels,
        routing_tunnels,
    )


if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")
    for a in adapters():
        if a["up"]:
            print("%-22s idx=%-4d %-18s ipv4=%-18s шлюз %s"
                  % (a["name"][:22], a["index"], a["description"][:18],
                     ",".join(a["ipv4"]) or "-", ",".join(a["gateways"]) or "-"))
