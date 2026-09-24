#!/usr/bin/env bash
# Запуск агента в песочнице systemd.
#
# Юнит временный (transient): он не записывается ни в /etc, ни в ~/.config,
# не включается при загрузке и исчезает сам после остановки или перезагрузки.
# Песочница не даёт процессу писать никуда, кроме собственного каталога, —
# поэтому удаление этого каталога гарантированно убирает всё, что агент мог
# создать.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT="mobile-ping-agent"

if systemctl --user is-active --quiet "$UNIT"; then
  echo "агент уже работает; журнал: $DIR/agent.out"
  exit 0
fi
systemctl --user reset-failed "$UNIT" 2>/dev/null || true

systemd-run --user --unit="$UNIT" --collect --quiet \
  --working-directory="$DIR" \
  -p Description="mobile-ping agent (песочница, $DIR)" \
  -p ProtectSystem=strict \
  -p ProtectHome=read-only \
  -p ReadWritePaths="$DIR" \
  -p PrivateTmp=yes \
  -p NoNewPrivileges=yes \
  -p Restart=on-failure -p RestartSec=10 \
  -p StandardOutput=append:"$DIR/agent.out" \
  -p StandardError=append:"$DIR/agent.out" \
  -E PYTHONDONTWRITEBYTECODE=1 \
  -E PYTHONUNBUFFERED=1 \
  /usr/bin/python3 "$DIR/agent.py"

sleep 3
if systemctl --user is-active --quiet "$UNIT"; then
  echo "агент запущен в песочнице ($UNIT); журнал: $DIR/agent.out"
else
  echo "агент не поднялся, последние строки журнала:" >&2
  tail -20 "$DIR/agent.out" >&2 || true
  exit 1
fi
