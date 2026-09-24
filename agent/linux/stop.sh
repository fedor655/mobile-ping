#!/usr/bin/env bash
# Остановить агента, ничего не удаляя. Запустить снова — start.sh.
set -uo pipefail
UNIT="mobile-ping-agent"

if systemctl --user is-active --quiet "$UNIT"; then
  systemctl --user stop "$UNIT"
  echo "агент остановлен"
else
  echo "агент не запущен"
fi
systemctl --user reset-failed "$UNIT" 2>/dev/null || true
