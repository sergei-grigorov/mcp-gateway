#!/bin/sh
# Выкладка шлюза и коннекторов на сервер: исходники → /opt/stack/agent, служба коннектора
# Ubuntu (ubuntu-mcp/deploy/install.sh), сборка образов, перезапуск контейнеров. Данные
# (data/, files/) и .env не трогаются.
#
#   DEPLOY_HOST=root@89.22.236.55 sh deploy/deploy.sh
#
# Нужны ssh-доступ к серверу и Docker Compose на нём. Первая выкладка — README шлюза.
set -eu
: "${DEPLOY_HOST:?укажите DEPLOY_HOST, например root@89.22.236.55}"
DIR=${DEPLOY_DIR:-/opt/stack/agent}
HERE=$(cd "$(dirname "$0")/.." && pwd)
CONNECTORS=$(cd "$HERE/.." && pwd)

# tar в macOS (bsdtar) иначе кладёт в архив атрибуты файлов и служебные файлы ._*.
TAR_MAC=""
tar --version 2>/dev/null | grep -q bsdtar && TAR_MAC="--no-xattrs --no-mac-metadata"

pack() {
  # Только то, что нужно для сборки образа: без .git, тестов, node_modules и пакетов.
  # shellcheck disable=SC2086
  COPYFILE_DISABLE=1 tar $TAR_MAC -C "$CONNECTORS" -czf - \
    --exclude=node_modules --exclude=.git --exclude=test --exclude=dist --exclude=scripts \
    --exclude=migrate --exclude='*.log' --exclude=.DS_Store \
    mcp-gateway bybit-mcp telegram-mcp ubuntu-mcp yandex-tracker-mcp
}

pack | ssh "$DEPLOY_HOST" "set -e
  mkdir -p $DIR && cd $DIR
  rm -rf gateway mcp-gateway bybit-mcp telegram-mcp ubuntu-mcp yandex-tracker-mcp
  tar -xzf -
  cp mcp-gateway/deploy/docker-compose.yml docker-compose.yml
  mkdir -p data/gateway data/bybit data/telegram data/ubuntu data/tracker files/telegram
  chown -R 1000:1000 data files && chmod 700 data/* files/*
  test -f .env || { echo 'нет .env (PUBLIC_URL, GATEWAY_SECRET) — см. README шлюза'; exit 1; }
  sh ubuntu-mcp/deploy/install.sh
  docker compose build --pull
  docker compose up -d --remove-orphans
  docker image prune -f >/dev/null
  docker builder prune -f >/dev/null
  docker compose ps"
