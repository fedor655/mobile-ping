#!/usr/bin/env bash
# Полный откат одной командой:
#
#     bash ~/mobile-ping/uninstall.sh
#
# или, если этого файла уже нет, то же самое вручную:
#
#     systemctl --user stop mobile-ping-agent; rm -rf ~/mobile-ping
#
# Больше удалять нечего. Агент работает во временном юните systemd, который
# не сохраняется на диске и исчезает после остановки, а песочница не даёт ему
# писать никуда, кроме своего каталога.
#
# Процесс опознаётся только по имени юнита. Поиск по имени файла (pkill -f
# agent.py) здесь намеренно не используется: он убил бы и посторонние
# программы с таким же именем, и даже сам себя.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT="mobile-ping-agent"

if systemctl --user is-active --quiet "$UNIT"; then
  systemctl --user stop "$UNIT"
  echo "агент остановлен"
fi
systemctl --user reset-failed "$UNIT" 2>/dev/null || true

# Защита от опечатки: удаляем только каталог, в котором лежит этот скрипт и
# агент. Пустой путь, корень или домашний каталог целиком — отказ.
if [[ -z "$DIR" || "$DIR" == "/" || "$DIR" == "$HOME" || ! -f "$DIR/agent.py" ]]; then
  echo "каталог $DIR не похож на установку агента — удалять не буду" >&2
  exit 1
fi

cd /
rm -rf -- "$DIR"
echo "каталог $DIR удалён — машина вернулась в исходное состояние"
