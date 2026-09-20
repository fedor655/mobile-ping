# -*- coding: utf-8 -*-
"""
deploy.py — залить серверную часть на VPS и запустить установку.

    python tools/deploy.py root@ВАШ_СЕРВЕР

Пароль берётся из переменной окружения MP_SSH_PASS, иначе спрашивается.
Если настроен ssh-ключ, пароль не нужен. Никаких секретов в файле нет.

Нужен paramiko:  pip install paramiko
"""

import argparse
import getpass
import io
import os
import posixpath
import sys

# Вывод systemd содержит символы, которых нет в кодировке консоли Windows.
for _stream in ("stdout", "stderr"):
    _s = getattr(sys, _stream)
    if hasattr(_s, "buffer"):
        setattr(sys, _stream, io.TextIOWrapper(_s.buffer, encoding="utf-8",
                                               errors="replace",
                                               line_buffering=True))

try:
    import paramiko
except ImportError:
    raise SystemExit("нужен paramiko: pip install paramiko")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_SERVER = os.path.join(HERE, "server")
REMOTE_ROOT = "/opt/mobile-ping"
REMOTE_SERVER = REMOTE_ROOT + "/server"

# то, что на сервере не нужно и не должно туда попадать
SKIP_DIRS = {"__pycache__", ".git"}
SKIP_EXT = {".db", ".db-wal", ".db-shm", ".pyc", ".log"}


def mkdirs(sftp, path):
    parts, cur = path.strip("/").split("/"), ""
    for p in parts:
        cur += "/" + p
        try:
            sftp.stat(cur)
        except IOError:
            sftp.mkdir(cur)


def upload_tree(sftp, local, remote):
    sent = 0
    for root, dirs, files in os.walk(local):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel = os.path.relpath(root, local).replace("\\", "/")
        rdir = remote if rel == "." else posixpath.join(remote, rel)
        mkdirs(sftp, rdir)
        for name in files:
            if os.path.splitext(name)[1] in SKIP_EXT:
                continue
            rpath = posixpath.join(rdir, name)
            sftp.put(os.path.join(root, name), rpath)
            if name.endswith(".sh"):
                sftp.chmod(rpath, 0o755)
            sent += 1
    return sent


def run(client, cmd, check=True):
    _, out, err = client.exec_command(cmd, timeout=180)
    text = out.read().decode("utf-8", "replace")
    errs = err.read().decode("utf-8", "replace")
    code = out.channel.recv_exit_status()
    if text.strip():
        print(text.rstrip())
    if errs.strip():
        print(errs.rstrip(), file=sys.stderr)
    if check and code != 0:
        raise SystemExit("команда завершилась с кодом %d: %s" % (code, cmd))
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="user@host")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--no-install", action="store_true",
                    help="только залить файлы, не запускать install.sh")
    args = ap.parse_args()

    user, _, host = args.target.rpartition("@")
    user = user or "root"
    password = os.environ.get("MP_SSH_PASS")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=args.port, username=user, timeout=25)
    except paramiko.AuthenticationException:
        if not password:
            password = getpass.getpass("пароль для %s@%s: " % (user, host))
        client.connect(host, port=args.port, username=user, password=password,
                       timeout=25)

    try:
        sftp = client.open_sftp()
        mkdirs(sftp, REMOTE_SERVER)
        n = upload_tree(sftp, LOCAL_SERVER, REMOTE_SERVER)
        sftp.close()
        print("залито файлов: %d -> %s" % (n, REMOTE_SERVER))

        if not args.no_install:
            run(client, "bash %s/deploy/install.sh" % REMOTE_SERVER)
    finally:
        client.close()


if __name__ == "__main__":
    main()
