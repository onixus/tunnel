# Hysteria: Let’s Encrypt

Действующий адрес: **onixus-rf.duckdns.org:443/UDP** (`139.100.233.173`). Hysteria переведена с самоподписанного сертификата на Let’s Encrypt. Первоначальный сертификат действителен до 27 декабря 2026, 18:47:14 UTC. TrustTunnel также переведён на этот сертификат; детали приведены ниже.

## Клиенты

Обновите страницу H UI и импортируйте новый QR/ссылку своей учётной записи. Экспорт использует домен и `insecure=0` для всех аккаунтов, включая Android. Старые профили с IP в качестве имени TLS или закреплённым старым сертификатом необходимо заменить.

Параметры: сервер `onixus-rf.duckdns.org`, порт `443`, SNI `onixus-rf.duckdns.org`, проверка TLS включена. Ручной CA, сертификат и fingerprint больше не задаются: используется системное хранилище доверия. Пароль пользователя и salamander не изменены. Можно оставить IP адресом сервера, если SNI явно задан доменом.

Профиль Hiddify на рабочем Mac обновлён. Linux-клиент `192.168.68.120` при миграции ответил Connection refused на SSH: его конфигурация не обновлена. Для sing-box необходимо заменить TLS-блок Hysteria outbound на `{"enabled":true,"server_name":"onixus-rf.duckdns.org","insecure":false}`, удалив прежние `certificate`, `certificate_path` и pin; затем перезапустить клиент. Сохраните существующие исключения маршрутов.

## Выпуск и продление

Certbot установлен из пакетов Ubuntu; используется standalone HTTP-01, для него разрешён TCP 80. Порт не публикует админку. DNS домена должен указывать на VPN-сервер.

```sh
certbot certonly --standalone --non-interactive --agree-tos \
  --email onixus@live.ru -d onixus-rf.duckdns.org
certbot renew --dry-run --no-random-sleep-on-renew --cert-name onixus-rf.duckdns.org
systemctl list-timers certbot.timer
```

Источник сертификата и ключа — `/etc/letsencrypt/live/onixus-rf.duckdns.org/`. [Deploy-hook](../scripts/deploy-hysteria-cert) установлен в `/etc/letsencrypt/renewal-hooks/deploy/hysteria`, root, `0750`. Он копирует fullchain и ключ в существующие `/etc/hysteria/server.crt` и `server.key` с правами `root:hysteria`, `0644/0640`, затем перезапускает H UI. При успешном продлении VPN-клиенты кратко переподключаются. Глобальные права каталога Let’s Encrypt не расширены. См. [Certbot deploy hooks](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

`certbot.timer` включён. H UI по-прежнему читает TLS из штатных путей; ACL, SOCKS-выходы и резервный маршрут сохранены. В `/etc/systemd/system/h-ui.service.d/hiddify-export.conf` заданы `H_UI_PUBLIC_HOST=onixus-rf.duckdns.org` и пустой `H_UI_HIDDIFY_ACCOUNT`: обычный URI теперь работает без JSON с вложенным сертификатом.

Служебный native-клиент `/etc/hysteria/client.json` обновлён на домен и системные CA. Сквозная проверка через Hysteria с `insecure=false` вернула выходной IP `151.241.234.124`. Фактический экспорт H UI проверен: схема hysteria2, новый домен, insecure=0.

## Восстановление

Предыдущие сертификат, ключ, служебный клиент и drop-in сохранены в `/root/hysteria-before-letsencrypt/` (root-only). Возврат к ним потребует также вернуть старые клиентские профили. Не восстанавливайте самоподписанный сертификат поверх действующего без необходимости.

Тест продления `certbot renew --dry-run --no-random-sleep-on-renew --cert-name onixus-rf.duckdns.org` завершился успешно. Deploy-hook проверен при первичной установке действующего сертификата.

## TrustTunnel на том же сертификате

TrustTunnel также переведён на `onixus-rf.duckdns.org`, порт 8443 TCP/UDP. `conn_domain` использует этот домен, `cert_mode=external`. Сертификат Let’s Encrypt копируется в `/opt/trusttunnel-web/certs/live/onixus-rf.duckdns.org/` отдельным [deploy-hook](../scripts/deploy-trusttunnel-cert), установленным как `/etc/letsencrypt/renewal-hooks/deploy/trusttunnel`. Ключ имеет права `10001:10001`, `0640`. Встроенный watcher панели раз в 60 секунд проверяет сертификат и посылает SIGHUP endpoint при обновлении.

В compose задано `CLIENT_CA_FILE=""`: экспорт TOML использует системные CA, `hostname=onixus-rf.duckdns.org`, `skip_verification=false`, без закрепления прежнего самоподписанного сертификата. Старые профили TrustTunnel нужно заново скачать или отправить из UI. Резервная копия compose: `/root/trusttunnel-before-letsencrypt/`; предыдущие TLS-настройки: `/opt/trusttunnel-web/data/tls-before-letsencrypt.json`.

Клиент Linux теперь находится на **192.168.68.116**; его Hysteria-профиль уже обновлён и проверен. Ранее упомянутая недоступность `.120` относится к старому адресу.

### Проверка доступности панелей

С `.116` через Hysteria SOCKS `127.0.0.1:10808` выполнено по 15 запросов к `http://10.254.77.1:8081/` и `http://10.254.77.1:18082/admin/login`: 30/30 ответов HTTP 200, максимум 66 мс. Это короткая серия проверок, не длительный мониторинг стабильности.

Через TrustTunnel приватные панели **недоступны**: `allow_private_network_connections=false` отклоняет такие назначения (SOCKS ошибка 5). Это действующая изоляция, а не TLS-сбой. Для панелей используйте Hysteria или SSH. Общее разрешение доступа к приватной сети не включалось.
