# -*- coding: utf-8 -*-
"""
bench.py — где предел у конкретного канала.

Отвечает на вопрос «сколько адресов в секунду мы реально можем пинговать».
Важно не то, сколько пакетов удастся вытолкнуть, а до какого темпа замерам
ещё можно верить: как только мы начинаем мешать сами себе, растут потери и
задержка, и таблица доступности превращается в выдумку.

Поэтому меряются три вещи сразу: достигнутый темп, доля потерь и задержка.
Потолком считается последняя ступень, на которой потери не выросли, а p95
задержки не раздулся вдвое против спокойного замера.

    python bench.py --adapter "Ethernet 4"
    python bench.py --adapter Ethernet --max 2000 --probes 400
"""

import argparse
import io
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import netinfo
import probe

# Cloudflare анонсирует весь 1.1.1.0/24, отвечает любой адрес из него.
# Нужен именно отвечающий набор: на молчащих целях меряется таймаут, а не канал.
TARGETS = ["1.1.1.%d" % i for i in range(1, 255)]

# Один echo с 32 байтами данных — 74 байта на проводе вместе с заголовками.
BYTES_ON_WIRE = 74


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))
    return s[k]


def step(src_ip, workers, probes, timeout_ms):
    """Одна ступень: probes пингов в workers потоков. Возвращает замеры."""
    targets = [TARGETS[i % len(TARGETS)] for i in range(probes)]
    rtts, lost = [], 0

    def one(t):
        r = probe.icmp_ping(t, src_ip, count=1, timeout_ms=timeout_ms,
                            gap_sec=0)
        return r["rtt_avg"] if r["recv"] else None

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for rtt in pool.map(one, targets):
            if rtt is None:
                lost += 1
            else:
                rtts.append(rtt)
    dt = time.perf_counter() - t0

    return {
        "workers": workers,
        "sec": dt,
        "rate": probes / dt if dt else 0.0,
        "loss": 100.0 * lost / probes,
        "p50": percentile(rtts, 50),
        "p95": percentile(rtts, 95),
    }


def tcp_step(src_ip, workers, probes, timeout):
    """Одна ступень для TCP: probes соединений в workers потоков."""
    def one(_):
        return probe.tcp_check("1.1.1.1", 443, src_ip, timeout=timeout)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        res = list(pool.map(one, range(probes)))
    dt = time.perf_counter() - t0
    ok = [r["ms"] for r in res if r["ok"]]
    return {"workers": workers, "rate": probes / dt if dt else 0.0,
            "loss": 100.0 * (probes - len(ok)) / probes,
            "p50": percentile(ok, 50), "p95": percentile(ok, 95)}


def main():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace", line_buffering=True)
    ap = argparse.ArgumentParser(description="предел темпа для одного канала")
    ap.add_argument("--adapter", required=True,
                    help="имя адаптера, MAC или однозначная подстрока")
    ap.add_argument("--probes", type=int, default=300,
                    help="пингов на ступень (по умолчанию 300)")
    ap.add_argument("--max", type=int, default=1000,
                    help="максимум потоков (по умолчанию 1000)")
    ap.add_argument("--timeout", type=int, default=2000,
                    help="таймаут одного пинга, мс")
    args = ap.parse_args()

    found = netinfo.match_adapters(args.adapter)
    if len(found) != 1:
        raise SystemExit("нужен ровно один адаптер, подошло %d: %s"
                         % (len(found), ", ".join(a["name"] for a in found)))
    adapter = found[0]
    src_ip = netinfo.usable_ipv4(adapter)
    if not src_ip:
        raise SystemExit("у адаптера %s нет рабочего адреса" % adapter["name"])

    eg = probe.egress_info(src_ip, timeout=3, budget=8)
    print("адаптер: %s (%s)" % (adapter["name"], adapter["description"]))
    print("адрес:   %s -> внешний %s %s"
          % (src_ip, eg["ip"] or "не определился", eg["info"]))
    print("пингов на ступень: %d, таймаут %d мс\n" % (args.probes, args.timeout))

    print("  потоков   темп, /с   потери   задержка p50 / p95")
    print("  " + "-" * 52)

    steps = [w for w in (1, 8, 32, 64, 128, 256, 500, 1000, 2000)
             if w <= args.max]
    rows = []
    for w in steps:
        r = step(src_ip, w, args.probes, args.timeout)
        rows.append(r)
        print("  %-9d %-10.1f %-8.1f %s / %s мс"
              % (r["workers"], r["rate"], r["loss"],
                 round(r["p50"]) if r["p50"] is not None else "—",
                 round(r["p95"]) if r["p95"] is not None else "—"))
        # На заведомо перегруженном канале дальше лезть незачем.
        if r["loss"] > 25:
            print("  (потери выше 25% — дальше не иду)")
            break
        time.sleep(1.0)          # дать каналу успокоиться между ступенями

    # Потолок: последняя ступень без заметных потерь и без раздувания задержки
    base = rows[0]
    good = [r for r in rows
            if r["loss"] <= max(2.0, base["loss"] + 1.0)
            and (r["p95"] is None or base["p95"] is None
                 or r["p95"] <= base["p95"] * 2 + 20)]
    best = max(good, key=lambda r: r["rate"]) if good else rows[0]

    print("\nдостоверный потолок: около %.0f адресов/с (%d потоков, "
          "потери %.1f%%, p95 %s мс)"
          % (best["rate"], best["workers"], best["loss"],
             round(best["p95"]) if best["p95"] else "—"))
    mbit = best["rate"] * BYTES_ON_WIRE * 8 / 1e6
    print("это %.2f Мбит/с — в ширину канала такой замер не упирается,"
          % mbit)
    print("предел задаёт темп пакетов, а не объём трафика.")

    # TCP ведёт себя совсем иначе: каждое соединение занимает запись в таблице
    # NAT телефона, и она кончается куда раньше, чем канал.
    print("")
    print("TCP: каждое соединение держит запись в NAT телефона")
    print("  потоков   темп, /с   неудач   задержка p50 / p95")
    print("  " + "-" * 52)
    tcp_rows = []
    for w in (32, 64, 128, 192, 320, 500):
        if w > args.max:
            break
        r = tcp_step(src_ip, w, min(args.probes, 300), 3.0)
        tcp_rows.append(r)
        print("  %-9d %-10.1f %-8.1f %s / %s мс"
              % (r["workers"], r["rate"], r["loss"],
                 round(r["p50"]) if r["p50"] is not None else "—",
                 round(r["p95"]) if r["p95"] is not None else "—"))
        if r["loss"] > 20:
            print("  (неудач больше 20% — NAT телефона кончился, дальше нет смысла)")
            break
        time.sleep(1.5)

    clean = [r for r in tcp_rows if r["loss"] <= 1.0]
    if clean:
        safe = max(clean, key=lambda r: r["workers"])
        print("")
        print("безопасный parallel_tcp для этого телефона: %d (неудач %.1f%%)"
              % (safe["workers"], safe["loss"]))
        print("выше него замер начнёт врать про закрытые порты.")


if __name__ == "__main__":
    main()
