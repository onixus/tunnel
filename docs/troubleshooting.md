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

На выходном узле:

```sh
systemctl is-active wg-quick@wg-private hysteria-exit
ss -lntp
journalctl -u hysteria-exit -n 50 --no-pager
nft -c -f /etc/nftables.conf
```

На Linux-клиенте после инициализации TUN:

```sh
systemctl is-active sing-box
ip -brief address show hy-tun
curl --noproxy '*' --max-time 20 https://api.ipify.org
curl --proxy socks5h://127.0.0.1:10808 --max-time 20 -I https://telegram.org
curl --noproxy '*' --max-time 10 -I http://10.254.77.1:18082/admin/login
```

Ожидаемый внешний IP берите из профиля выбранного выхода. В прямом режиме
это адрес входного сервера. TCP connect и SOCKS response не заменяют
HTTPS-запрос через туннель с полноценным ответом.

## Симптомы

| Симптом | Что проверить |
|---|---|
| VPN подключился, сайты не открываются | DNS, MTU, ACL, конечный outbound, firewall второго сервера |
| Hysteria auth failed | Пользователь активен, connection password, доступ ядра к локальному auth API |
| TLS/certificate error | SNI/IP SAN, часы, переданный CA/pin, срок; не отключайте проверку |
| WireGuard handshake есть, SOCKS timeout | Native nftables на выходном узле, правило TCP 1080, затем UDP relay |
| Панель не открывается через Hysteria | Маршрут 10.254.77.1/32 не bypass; port rule выше private→direct; ACL выше reject |
| Через SSH refused | Туннель завершён, локальный порт занят, служба панели остановлена |
| QUIC не работает, HTTP/2 работает | UDP 8443, ограничения сети/DPI, Docker mapping, MTU |
| Только крупные ответы зависают | Пакетные потери, PMTU; WG 1380, Hysteria TUN 1400, TT TUN 1280 — снижайте только после измерений |
| curl получает 403 от H UI | Панель фильтрует некоторые User-Agent; проверьте браузером, это не всегда сеть |
| Сразу после restart виден IP провайдера | TUN ещё не готов; проверьте маршруты и повторите после инициализации |
| Клиент TrustTunnel теряет туннель, на сервере пусто | Официальный endpoint не пишет закрытия сессий; с [патчем](endpoint-session-log.md) ищите `Session closed` с причиной и `Shutdown (SIGTERM)` в `docker logs trusttunnel-web` |
| Интерфейс работает, endpoint остановился | Container health проверяет HTTP панели, не сквозную VPN-передачу |
| Сайт требует отключить VPN | Проверьте репутацию адреса и ASN, согласованность маршрута сайта/API/капчи и IPv6. Direct на сервере всё ещё использует адрес сервера; клиентский обход использует провайдера устройства. См. [антибот-защиту](antibot.md) |

Не очищайте nftables/iptables целиком для диагностики. Проверяйте пакет на конкретном интерфейсе и порту; не сохраняйте payload с приватным трафиком без необходимости.

## Проверка исключений

Клиентский direct-обход может скрыть результат серверного правила. Для проверки
**серверного** исключения используйте отдельный SOCKS-клиент без TUN и локальных
domain-direct правил. Обращайтесь через `socks5h`, передавая имя серверу.
При захвате заголовков проверьте источник на входном сервере и на транспорте
к выходу. Учитывайте выбранную политику, а не фиксированный адрес из примера.

После изменения проверьте DNS, HTTPS, нужные UDP-приложения, панели, отзыв
тестового доступа и восстановление сети после отключения клиента. Результат
одного устройства не подтверждает работу всех ОС и сетей.
