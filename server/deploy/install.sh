#!/usr/bin/env bash
# Установка серверной части mobile-ping. Запускать на VPS от root.
#
#   scp -r server root@ВАШ_СЕРВЕР:/opt/mobile-ping/
#   ssh root@ВАШ_СЕРВЕР 'bash /opt/mobile-ping/server/deploy/install.sh'
#
# Скрипт идемпотентен: повторный запуск обновляет код и перезапускает службу,
# токен при этом сохраняется.

set -euo pipefail

PORT="${MP_PORT:-8091}"
ENV_FILE=/etc/mobile-ping.env
APP_DIR=/opt/mobile-ping/server
STATE_DIR=/var/lib/mobile-ping

if [[ $EUID -ne 0 ]]; then
  echo "нужны права root" >&2
  exit 1
fi

if ! id -u mobile-ping >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin mobile-ping
  echo "создан системный пользователь mobile-ping"
fi

install -d -o mobile-ping -g mobile-ping "$STATE_DIR"
chown -R root:root /opt/mobile-ping

# Токен генерируем один раз и больше не трогаем: он прописан у агентов.
if [[ ! -f "$ENV_FILE" ]]; then
  TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  cat > "$ENV_FILE" <<EOF
MP_TOKEN=$TOKEN
MP_PORT=$PORT
MP_HOST=0.0.0.0
MP_DB=$STATE_DIR/mobile-ping.db
MP_STATIC=$APP_DIR/static
EOF
  chmod 600 "$ENV_FILE"
  echo "создан $ENV_FILE, токен сгенерирован"
fi

install -m 644 "$APP_DIR/deploy/mobile-ping.service" \
  /etc/systemd/system/mobile-ping.service

systemctl daemon-reload
systemctl enable mobile-ping >/dev/null
systemctl restart mobile-ping

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow "$PORT/tcp" comment 'mobile-ping' >/dev/null || true
fi

sleep 1
systemctl --no-pager --lines=5 status mobile-ping || true

echo
echo "готово. сайт: http://$(hostname -I | awk '{print $1}'):$PORT"
echo "токен для агента:"
grep '^MP_TOKEN=' "$ENV_FILE" | cut -d= -f2-
