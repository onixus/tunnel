# Проверки и диагностика

## Минимальная приёмка

На входном сервере:

```sh
systemctl is-active h-ui wg-quick@wg-private
wg show wg-private
ss -lntup
docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' trusttunnel-web
docker logs --tail 60 trusttunnel-web
```

На onixus.ru:

```sh
systemctl is-active wg-quick@wg-private hysteria-exit
ss -lntp
journalctl -u hysteria-exit -n 50 --no-pager
nft -c -f /etc/nftables.conf
```

На `.120` после инициализации TUN:

```sh
systemctl is-active sing-box
ip -brief address show hy-tun
curl --noproxy '*' --max-time 20 https://api.ipify.org
curl --proxy socks5h://127.0.0.1:10808 --max-time 20 -I https://telegram.org
curl --noproxy '*' --max-time 10 -I http://10.254.77.1:18082/admin/login
```

Hysteria: ожидаемый внешний IP `151.241.234.124`; TrustTunnel SOCKS-тест из [клиентской инструкции](clients.md): `139.100.233.173`. Один успешный TCP connect/SOCKS response недостаточен — выполните HTTPS-запрос с ответом.

## Симптомы

| Симптом | Что проверить |
|---|---|
| VPN подключился, сайты не открываются | DNS, MTU, ACL, конечный outbound, firewall второго сервера |
| Hysteria auth failed | Пользователь активен, connection password, доступ ядра к локальному auth API |
| TLS/certificate error | SNI/IP SAN, часы, переданный CA/pin, срок; не отключайте проверку |
| WireGuard handshake есть, SOCKS timeout | Native nftables на onixus.ru, правило TCP 1080, затем UDP relay |
| Панель не открывается через Hysteria | Маршрут 10.254.77.1/32 не bypass; port rule выше private→direct; ACL выше reject |
| Через SSH refused | Туннель завершён, локальный порт занят, служба панели остановлена |
| QUIC не работает, HTTP/2 работает | UDP 8443, ограничения сети/DPI, Docker mapping, MTU |
| Только крупные ответы зависают | Пакетные потери, PMTU; WG 1380, Hysteria TUN 1400, TT TUN 1280 — снижайте только после измерений |
| curl получает 403 от H UI | Панель фильтрует некоторые User-Agent; проверьте браузером, это не всегда сеть |
| Сразу после restart виден IP провайдера | TUN ещё не готов; проверьте маршруты и повторите после инициализации |
| Клиент TrustTunnel теряет туннель, на сервере пусто | Официальный endpoint не пишет закрытия сессий; с [патчем](endpoint-session-log.md) ищите `Session closed` с причиной и `Shutdown (SIGTERM)` в `docker logs trusttunnel-web` |
| Интерфейс работает, endpoint остановился | Container health проверяет HTTP панели, не сквозную VPN-передачу |
| Кинопоиск: «У вас включен VPN или в вашей стране доступен не весь каталог» | Маршрутизация не виновата: GraphQL `OttData` → `contentAvailability.geo.availabilityStatus` = `RESTRICTED` и для российского адреса onixus-rf (Selectel AS49505), и для выходов — Кинопоиск отсекает адреса хостингов. Яндекс должен идти с домашнего провайдера: R-TrustTunnel в режиме TUN с группой «Маршруты устройств», исключающей сети AS13238 (2026-10-26: группа «Яндекс напрямую» для Windows-устройства) |

Не очищайте nftables/iptables целиком для диагностики. Проверяйте пакет на конкретном интерфейсе и порту; не сохраняйте payload с приватным трафиком без необходимости.

## Проверка исключений

`.ru` на `.120` обходит сервер локально. Чтобы проверить **серверное** правило, используйте отдельный Hysteria SOCKS-клиент без TUN и без локальных domain-direct правил. Обращайтесь через `socks5h`, передавая имя серверу. На входном узле захват TCP-заголовков должен показать прямое соединение с источником `139.100.233.173` к IP сайта; для обычного иностранного сайта должен использоваться WG/SOCKS.

## Фактические результаты 28.09.2026

- Hysteria: HTTPS через `.120` и отдельный native client, IP `151.241.234.124`.
- `.ru` (`ya.ru`) и `.рф` (`кц.рф`): ответы 302/200, прямые пакеты с `139.100.233.173`.
- IP `77.88.8.8`: прямой маршрут GeoIP RU; остальные девять стран по отдельности не тестировались.
- UDP DNS к `1.1.1.1` и `77.88.8.8` через Hysteria: ответы получены.
- Telegram: сайты отвечают; пять DC вернули начальный MTProto `resPQ`, 145–439 мс. Отправка сообщений, медиа и звонки не тестировались.
- TrustTunnel Client 1.1.7: HTTP/2 и QUIC с проверкой сертификата, IP `139.100.233.173`; Telegram по HTTP/2 доступен.
- Панели: логины и экспорт TOML успешны, HTTP через Hysteria доступен, публичные порты управления не доступны.

Эти результаты — снимок, не постоянный мониторинг и не SLA.
