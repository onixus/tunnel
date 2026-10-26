# Hysteria 2 и H UI

Для публичного сертификата см. [Let’s Encrypt](hysteria-letsencrypt.md);
ниже также приведён пример с самоподписанным сертификатом.

При использовании **H UI** панель сама запускает ядро; отдельная
`hysteria-server.service` для него не нужна. Не запускайте обе службы на UDP 443.

## Установка с нуля

Предварительно настройте [WireGuard и SOCKS5](interserver.md). Установите `curl`, `ca-certificates`, `openssl`, `python3`, `python3-yaml`. Все команды установки выполняются на входном сервере с правами root.

1. Скачайте Hysteria 2.12.3 и H UI 0.0.25 из официальных релизов, сверьте [SHA256](versions.md). Не выполняйте непроверенный install-скрипт через pipe в shell.
2. Установите Hysteria в `/usr/local/bin/hysteria`, H UI в `/usr/local/bin/h-ui`, оба root:root `0755`.
3. Создайте системного пользователя `hysteria` без shell, каталоги `/etc/hysteria` (root:hysteria `0750`) и `/var/lib/h-ui/{bin,data,logs,export,geo}` (hysteria:hysteria `0750`). Скопируйте ядро в `/var/lib/h-ui/bin/hysteria-linux-amd64`.
4. Выпустите отдельный сертификат (пример ниже) либо установите управляемый публичный сертификат. На существующем сервере сертификат **не заменяйте**, иначе нарушится доверие действующих клиентов.
5. Установите [unit H UI](../examples/systemd/h-ui.service). До первого запуска запретите вход на TCP 8081 из публичной сети и разрешите UDP 443. Сохраните доступ SSH и работающую сессию перед изменением firewall.
6. Скачайте GeoIP и проверьте контрольную сумму. Владельцем файла должен быть `hysteria`, путь `/var/lib/h-ui/geo/geoip.dat`.
7. Инициализируйте панель, задайте случайные пароль администратора, connection password администратора и JWT-secret. Для новой установки используйте [bootstrap](../scripts/bootstrap-hui.py) после краткого первого старта и **остановки** H UI. Скрипт откажется работать при активной службе.
8. Запустите H UI и подключитесь через [SSH](panels.md). Создайте отдельного пользователя VPN. Задайте конфигурацию ядра на основе [шаблона](../examples/hysteria-server.yaml), подставив SOCKS-пароль и salamander-пароль. Панель должна сохранить HTTP-auth и локальный trafficStats; их secret управляется H UI.
9. Включите ядро через панель и выполните [проверки](troubleshooting.md).

Пример генерации нового самоподписанного сертификата с IP SAN:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -days 365 -subj /CN=192.0.2.10 \
  -addext subjectAltName=IP:192.0.2.10 \
  -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt
chown root:hysteria /etc/hysteria/server.key /etc/hysteria/server.crt
chmod 640 /etc/hysteria/server.key /etc/hysteria/server.crt
```

Первичная инициализация H UI (только новая установка):

```sh
ufw insert 1 deny 8081/tcp
ufw allow 443/udp
systemctl daemon-reload
systemctl start h-ui
systemctl stop h-ui
python3 scripts/bootstrap-hui.py
systemctl enable --now h-ui
```

Скрипт из репозитория запускайте из каталога его клона на сервере. Секреты сохраняются только в `/root/h-ui-bootstrap.json` с правами `0600` и не печатаются. Он отключает ядро до ручной настройки; **не применяйте его на рабочей базе**.

## Рабочая конфигурация

Источник состояния панели — `/var/lib/h-ui/data/h_ui.db`, в `config` хранится `HYSTERIA2_CONFIG`. Редактирование старого `/etc/hysteria/server.json` не меняет запущенное панелью ядро. Обычно используйте UI. Если нужна аварийная правка SQLite, сначала остановите H UI и сделайте backup.

- Авторизация: `http://127.0.0.1:8081/hui/hysteria2/auth`.
- Статистика: только `127.0.0.1:9999`, с отдельным secret.
- Транспорт: UDP 443, salamander; TLS проверяется клиентом.
- GeoIP: `/var/lib/h-ui/geo/geoip.dat`, без автоматического обновления.
- Прямой outbound — IPv4; основной — SOCKS5 через WG.
- Порядок ACL критичен: доступ к двум панелям должен стоять выше запрета приватных IP.

Unit оставляет только `CAP_NET_BIND_SERVICE`; порт-хоппинг не включён. Сообщение панели о невозможности создать nft-таблицу для port hopping не означает отказ обычного Hysteria. Не добавляйте `CAP_NET_ADMIN` ради устранения этого сообщения.

## Существующие пользователи

Выдавайте отдельные учётные записи, чтобы отзыв одного устройства
не затрагивал остальных. Пароль входа в UI, connection password пользователя, salamander и SOCKS-пароль — разные секреты.

Самоподписанный сертификат требует передачи доверенного публичного `server.crt` клиенту или корректного fingerprint. Экспорт H UI сам по себе может не содержать это доверие. Не исправляйте TLS-ошибки постоянным `insecure=true`.
