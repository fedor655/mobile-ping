# -*- coding: utf-8 -*-
"""
deploy_agent_linux.py — поставить агента на Linux-машину в один каталог.

    MP_SSH_PASS=... python tools/deploy_agent_linux.py user@host \\
        --config путь/к/agent.config.json [--start]

Что делает и чего не делает:

* всё кладёт в один каталог (по умолчанию ~/mobile-ping) и больше никуда;
* root не нужен и не используется, пакеты не ставятся, настройки системы
  и сети не меняются;
* запуск (--start) — во временном юните systemd с песочницей, который не
  сохраняется на диске и не включается при загрузке;
* откат одной командой: bash ~/mobile-ping/uninstall.sh

Заливаются только файлы, нужные под Linux: виндовые модули агента там не
импортируются, и держать их на машине незачем. Переводы строк приводятся к
LF — с CRLF bash-скрипт на Linux не запускается вовсе.

Нужен paramiko: pip install paramiko
"""

import argparse
import getpass
import io
import os
import posixpath
import sys

for _name in ("stdout", "stderr"):
    _s = getattr(sys, _name)
    if hasattr(_s, "buffer"):
        setattr(sys, _name, io.TextIOWrapper(_s.buffer, encoding="utf-8",
                                             errors="replace",
                                             line_buffering=True))

try:
    import paramiko
except ImportError:
    raise SystemExit("нужен paramiko: pip install paramiko")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "agent")

# Что нужно агенту под Linux. Остальное в agent/ — для Windows.
AGENT_FILES = [
    "agent.py", "probe.py", "netinfo.py", "netinfo_linux.py",
    "icmp_linux.py", "consts.py", "bench.py", "agent.config.example.json",
]
SCRIPTS = ["start.sh", "stop.sh", "uninstall.sh"]


def read_lf(path):
    with open(path, "rb") as fh:
        return fh.read().replace(b"\r\n", b"\n")


def run(client, cmd):
    _, out, err = client.exec_command(cmd, timeout=120)
    text = out.read().decode("utf-8", "replace")
    text += err.read().decode("utf-8", "replace")
    return out.channel.recv_exit_status(), text


def main():
    ap = argparse.ArgumentParser(description="агент mobile-ping на Linux")
    ap.add_argument("target", help="user@host")
    ap.add_argument("--dir", default="mobile-ping",
                    help="каталог относительно домашнего (по умолчанию mobile-ping)")
    ap.add_argument("--config", help="локальный agent.config.json для заливки")
    ap.add_argument("--start", action="store_true",
                    help="сразу запустить в песочнице")
    args = ap.parse_args()

    user, _, host = args.target.rpartition("@")
    password = os.environ.get("MP_SSH_PASS") or getpass.getpass(
        "пароль %s@%s: " % (user, host))

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=25)
    try:
        code, home = run(client, "printf %s \"$HOME\"")
        remote = posixpath.join(home.strip(), args.dir)
        run(client, "mkdir -p %s" % remote)

        sftp = client.open_sftp()
        for name in AGENT_FILES:
            with sftp.open(posixpath.join(remote, name), "wb") as fh:
                fh.write(read_lf(os.path.join(AGENT, name)))
        for name in SCRIPTS:
            dst = posixpath.join(remote, name)
            with sftp.open(dst, "wb") as fh:
                fh.write(read_lf(os.path.join(AGENT, "linux", name)))
            sftp.chmod(dst, 0o755)
        if args.config:
            dst = posixpath.join(remote, "agent.config.json")
            with sftp.open(dst, "wb") as fh:
                fh.write(read_lf(args.config))
            sftp.chmod(dst, 0o600)          # там токен сервера
        sftp.close()
        print("залито в %s: %d файлов%s" % (
            remote, len(AGENT_FILES) + len(SCRIPTS),
            " + настройки" if args.config else ""))

        if args.start:
            code, text = run(client, "bash %s/start.sh" % remote)
            print(text.strip())
            if code != 0:
                raise SystemExit(code)
        print("откат: bash %s/uninstall.sh" % remote)
    finally:
        client.close()


if __name__ == "__main__":
    main()
