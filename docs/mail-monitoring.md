# Почта и мониторинг VPN

Настроено 28 сентября 2026 года. Получатель: `onixus@live.ru`.

## Отправка

TrustTunnel и мониторинг используют существующий Maddy на `mail.onixus.ru` (узел `151.241.234.124`), SMTP SSL, порт 465. Выделенный отправитель и логин — `vpn-reports@onixus.ru`. Учётка создана штатной командой Maddy; публичный relay без авторизации не включался. См. [документацию Maddy](https://maddy.email/tutorials/setting-up/).

SMTP настроен в базе TrustTunnel через `db.set_settings`: `smtp_host`, `smtp_port`, `smtp_tls=ssl`, `smtp_user`, `smtp_password`, `smtp_from`. Проверять можно в [настройках админки](http://127.0.0.1:18082/admin/settings) через SSH-туннель.

Пароль мониторинга хранится в `/etc/vpn-report/smtp.json` на обоих узлах: каталог `0700`, файл `0600`, root. Резервная исходная запись SMTP-учётки на onixus.ru — `/root/vpn-reports-smtp.json`, `0600`. Секреты в репозиторий не копируются. При ротации обновляются оба файла конфигурации, исходная запись и настройки TrustTunnel.

## Расписание

На VPN-сервере:

- `vpn-report-daily.timer`: ежедневно **09:00 Europe/Moscow**, `Persistent=true`; пропущенная сводка отправляется после включения сервера. Следующая после настройки: 29 сентября 2026, 09:00 МСК.
- `vpn-report-check.timer`: проверка каждую минуту, точность таймера 5 секунд. Остановка службы или недоступность ядра вызывает письмо при ближайшей проверке.
- Повтор того же аварийного уведомления — не чаще раза в 30 минут. Восстановление сопровождается отдельным письмом.

На onixus.ru работает только `vpn-report-check.timer`: проверяет собственные Maddy, hysteria-exit и основной WireGuard, а также SSH-доступность VPN-сервера снаружи. Эта проверка обнаруживает недоступность узла; она не заменяет сквозной тест Hysteria с клиентского устройства.

Логи остаются на исходных серверах, отдельного хранилища на onixus.ru нет. В письмах — выдержки операционных событий за 24 часа: количество соединений/ошибок Hysteria, последние 30 подключений/отключений и Ban/Unban Fail2ban. Пароли, URL запросов и посещённые домены исключены из этих выдержек. Бан-лист относится к Fail2ban jail `sshd`, а не к блокировкам учётных записей VPN.

## Состав проверок

Сводка VPN-сервера: RAM, свободный диск, load average, число CPU, состояния H UI, ядра Hysteria (trafficStats), TrustTunnel, Fail2ban и WireGuard, возраст handshake, число онлайн-сессий и статистика банов SSH.

Пороговые предупреждения после двух последовательных проверок:

- RAM занято не менее 95%;
- корневой диск занят не менее 90%;
- load average за 5 минут больше удвоенного числа CPU;
- WireGuard handshake старше 180 секунд.

SMTP-передача подтверждена для двух тестов: сводки и письма из панели. В журнале Maddy обе записи имеют `delivered` для `onixus@live.ru`. Это подтверждение приёма почтовой системой получателя, а не прочтения или помещения во «Входящие».

Если сам Maddy или путь к нему недоступен, письмо не может уйти этим же каналом: аварийные проверки повторяются каждую минуту, ежедневная отправка повторяется через 5 минут при ошибке. Независимый второй канал уведомлений не настроен.

## Обслуживание

Код: [scripts/vpn-report.py](../scripts/vpn-report.py), установлен как `/usr/local/sbin/vpn-report`. Состояние подавления повторных писем: `/var/lib/vpn-report/state.json`. Монитор запускается root через systemd с `NoNewPrivileges`, `ProtectHome` и `ProtectSystem=strict`; запись разрешена в `/var/lib/vpn-report`.

```sh
systemctl list-timers 'vpn-report-*'
journalctl -u vpn-report-check -u vpn-report-daily --since '1 hour ago'
# Отправить сводку вручную:
/usr/local/sbin/vpn-report daily
# Проверить доставку на onixus.ru:
journalctl -u maddy --since '10 minutes ago'
```

Отключить уведомления: `systemctl disable --now vpn-report-check.timer vpn-report-daily.timer` на VPN-сервере и `systemctl disable --now vpn-report-check.timer` на onixus.ru. Это не отключает почту панели.
