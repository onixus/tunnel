# TrustTunnel и trusttunnel-web

Инструкция восстановления текущего варианта на Ubuntu x86_64 с Docker Engine и Compose. Панель сторонняя; официальный endpoint — TrustTunnel 1.1.0. TCP/UDP 8443 не конфликтуют с Hysteria UDP 443.

## Подготовить исходники и образ

На новом сервере установите Docker Engine/Compose из доверенного источника, `git`, `curl`, `openssl`, `python3`. Сохраните этот репозиторий в отдельный административный каталог. Далее root:

```sh
git clone https://github.com/Ttolyanich/trusttunnel-web.git /opt/trusttunnel-web
cd /opt/trusttunnel-web
git checkout fd8c6efae205e3d3a77b5ae3a632b46a702cc661
```

Примените `patches/trusttunnel-web-local.patch` из **этого** репозитория: сначала `git apply --check /абсолютный/путь/к/patch`, затем `git apply /абсолютный/путь/к/patch`. Patch соответствует установленным локальным изменениям:

- официальный endpoint копируется в образ после проверки SHA256;
- контейнер работает как UID/GID 10001;
- выход IPv4, private network connections запрещены;
- TOML включает доверенный PEM без отключения проверки;
- `tt://?…` генерируется официальным endpoint, а не упрощённой сторонней схемой;
- в кабинете доступно скачивание TOML.

Скачайте архив endpoint 1.1.0 по ссылке из [versions](versions.md), проверьте SHA256, распакуйте во временный каталог и скопируйте `trusttunnel_endpoint` в `/opt/trusttunnel-web/trusttunnel_endpoint`, права `0755`. Patch Dockerfile ожидает этот файл **до сборки**.

```sh
cd /opt/trusttunnel-web
docker build -t trusttunnel-web:local-fd8c6ef-v1.1.0 .
```

Не обновляйте исходники до произвольного HEAD перед применением patch. Зафиксированные Python-зависимости взяты из upstream requirements; полная воспроизводимость base image/transitive dependencies не обеспечена.

## Каталоги и сертификат

```sh
cd /opt/trusttunnel-web
install -d -o 10001 -g 10001 -m 750 data data/runtime certs/live/trusttunnel.internal
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -days 365 -subj /CN=trusttunnel.internal \
  -addext subjectAltName=DNS:trusttunnel.internal,IP:139.100.233.173 \
  -keyout certs/live/trusttunnel.internal/privkey.pem \
  -out certs/live/trusttunnel.internal/fullchain.pem
chown 10001:10001 certs/live/trusttunnel.internal/*.pem
chmod 640 certs/live/trusttunnel.internal/*.pem
```

На восстановленном сервере используйте прежний сертификат/ключ из защищённой копии, чтобы клиенты сохранили доверие. Текущий сертификат действителен до **28.09.2027 00:00:48 UTC**. Продление автоматикой не настроено.

Скопируйте [Compose](../examples/trusttunnel-compose.yaml) в `/opt/trusttunnel-web/compose.yaml`. Сгенерируйте `.env` локально (не коммитьте):

```dotenv
ADMIN_EMAIL=admin@onixus.ru
ADMIN_PASSWORD=REPLACE_LOCALLY_RANDOM_ADMIN_PASSWORD
SECRET_KEY=REPLACE_LOCALLY_RANDOM_SESSION_SECRET
PUBLIC_ADDRESS=139.100.233.173
CLIENT_CA_FILE=/certs/live/trusttunnel.internal/fullchain.pem
ACCESS_TOKEN_TTL_MIN=480
```

Пароль — минимум 24 случайных символа, SECRET_KEY — минимум 32 случайных байта. `.env`: root:root `0600`. В отличие от bootstrap H UI, при наличии базы переменные ADMIN_* не заменяют уже созданного администратора.

## Инициализация

Сначала инициализируйте SQLite и настройки, чтобы не запустить панель с открытой регистрацией. Команда не содержит паролей — они берутся из `.env`:

```sh
cd /opt/trusttunnel-web
docker compose -f compose.yaml run --rm -T --no-deps trusttunnel-web python - <<'PY'
from app import db
import os
os.umask(0o077)
db.init_db()
db.set_settings({
    'panel_domain': 'trusttunnel.internal',
    'conn_domain': 'trusttunnel.internal',
    'conn_address': '139.100.233.173',
    'conn_port': '8443',
    'conn_protocol': 'HTTP2',
    'cert_mode': 'external',
    'registration_enabled': '0',
    'brand_name': 'Onixus TrustTunnel',
    'portal_url': 'http://10.254.77.1:18082',
})
PY
docker compose -f compose.yaml up -d
```

Администратор входит через SSH, создаёт пользователя и конфиг; только после этого появляется VPN credential. Откройте [панель](panels.md), получите профиль и выполните клиентский тест.

## Firewall и доступ

Разрешите публичные TCP+UDP 8443. Docker publish публикует их независимо от части правил UFW; проверьте фактическую экспозицию. Панель публикуется **только** `127.0.0.1:18082:8000`.

SSH: `-L 127.0.0.1:18082:127.0.0.1:18082`. Через Hysteria доступ обеспечивает ACL `local(10.254.77.1, tcp/18082, 127.0.0.1)` плюс явный маршрут на клиенте. Этот адрес не является публичной панелью; на `.120` маршрут уже настроен.

Через сам TrustTunnel private IP запрещены. Управляйте через SSH или Hysteria. Публичный домен для панели не настроен; SMTP и сторонние приложения портала не настроены.

## Проверки

```sh
cd /opt/trusttunnel-web
docker compose -f compose.yaml ps
docker logs --tail 60 trusttunnel-web
docker exec trusttunnel-web /opt/trusttunnel/trusttunnel_endpoint --version
curl --max-time 5 http://127.0.0.1:18082/healthz
```

В логах endpoint должны быть TCP и UDP `0.0.0.0:8443`. Затем выполните HTTP/2 и QUIC тесты официальным клиентом по [инструкции](clients.md); ожидаемый IP — `139.100.233.173`. Healthcheck панели сам по себе не подтверждает VPN.

В данной установке ICMP и работа приложений на всех ОС не проверялись. HTTP/2, QUIC, TLS trust и HTTPS проверены с Linux.
