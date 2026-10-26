# Почта и мониторинг VPN

## SMTP

Подготовьте SMTP-аккаунт у своего провайдера. Пример параметров:
`mail.example.com`, TLS/SSL 465, отправитель `vpn-reports@example.com`,
получатель `admin@example.com`. Адреса и способ TLS замените настройками провайдера.
Публичный relay без авторизации не требуется.

В портале используются `smtp_host`, `smtp_port`, `smtp_tls`, `smtp_user`,
`smtp_password`, `smtp_from`. Настройки доступны администратору через портал.
Мониторинг читает `/etc/vpn-report/smtp.json`: каталог `0700`, файл root `0600`.
JSON содержит `host`, `port`, `user`, `password`, `from`, `to`, `role`
(`vpn` или `observer`). При ротации обновите все использующие аккаунт компоненты.

## Установка и расписание

Код: [vpn-report.py](../scripts/vpn-report.py), целевой путь
`/usr/local/sbin/vpn-report`. Шаблоны systemd:
[check.service](../examples/systemd/vpn-report-check.service),
[check.timer](../examples/systemd/vpn-report-check.timer),
[daily.service](../examples/systemd/vpn-report-daily.service),
[daily.timer](../examples/systemd/vpn-report-daily.timer).
Нужен Python 3; для VPN-роли также PyYAML. Создайте `/var/lib/vpn-report`
с правами `0700`. Перед включением проверьте пути, список служб и часовой пояс
в шаблонах. `Persistent=true` может отправить пропущенную сводку при запуске.

Сводка включает ресурсы узла, состояния служб и статистику VPN/Fail2ban.
Пороговые проверки и подавление повторов задаются реализацией монитора;
состояние хранится в `/var/lib/vpn-report/state.json`.
Роль observer позволяет проверять узел снаружи. Это не заменяет VPN-пробу
с клиентского устройства. Если SMTP недоступен, уведомление через тот же SMTP
не уйдёт; независимый второй канал настраивается отдельно.

## Обслуживание

```sh
systemctl list-timers 'vpn-report-*'
journalctl -u vpn-report-check -u vpn-report-daily --since '1 hour ago'
# Отправляет реальное письмо настроенному получателю:
/usr/local/sbin/vpn-report daily
```

Включайте необходимые timers после проверки конфигурации. Для остановки:
`systemctl disable --now vpn-report-check.timer vpn-report-daily.timer`.
Это не отключает SMTP портала. Подтверждение приёма SMTP не означает прочтение
или попадание во «Входящие»; проверяйте доставку у своего почтового провайдера.

## Отправка профилей из UI

Администратор может отправить пользователю собственные конфигурации на
сохранённый e-mail. Перед отправкой проверьте получателя: вложения содержат
VPN-доступ. Пароль веб-кабинета в письмо не включается. Для консоли см.
[доставку конфигураций](unified-console.md#отправка-конфигураций-на-e-mail-и-в-telegram).
Сбой после приёма SMTP может привести к дублю при ручном повторе.
Проверяйте функцию на отдельной тестовой учётной записи.
