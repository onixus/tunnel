# Приватный WireGuard и выходной SOCKS5

Сначала настройте оба узла, затем Hysteria. Для уже работающей установки используйте проверки, а не переустановку.

## WireGuard

На Ubuntu установите `wireguard-tools`. Под root на **каждом узле отдельно**:

```sh
install -d -m 700 /etc/wireguard
umask 077
wg genkey | tee /etc/wireguard/wg-private.key | wg pubkey > /etc/wireguard/wg-private.pub
```

Приватный ключ остаётся на своём узле. Передайте только публичный ключ партнёру. Заполните [шаблон входного узла](../examples/wireguard/ingress.conf) и [шаблон выходного узла](../examples/wireguard/exit.conf); установите как `/etc/wireguard/wg-private.conf`, права `0600`, владелец root.

До старта разрешите UDP 51830 только от публичного адреса партнёра. На входном сервере с UFW:

```sh
ufw allow in on eth0 from 198.51.100.10 to any port 51830 proto udp
ufw allow in on wg-private from 10.254.77.2 to 10.254.77.1
systemctl enable --now wg-quick@wg-private
wg show wg-private
ping -c 3 10.254.77.2
```

На выходном узле с nftables определите таблицу и input-цепочку через
`nft list ruleset`. В примере публичный адрес входа — `192.0.2.10`. Вставьте **перед финальным drop/reject**:

```nft
ip saddr 192.0.2.10 udp dport 51830 accept comment "Hysteria private WireGuard"
iifname "wg-private" ip saddr 10.254.77.1 ip daddr 10.254.77.2 tcp dport 1080 accept comment "Hysteria exit SOCKS"
iifname "wg-private" ip saddr 10.254.77.1 ip daddr 10.254.77.2 meta l4proto udp accept comment "Hysteria exit UDP relay"
```

Сохраните правила штатным для своей ОС способом. Если используется
`/etc/nftables.conf`, проверьте `nft -c -f /etc/nftables.conf`. Применяйте узкие
правила в фактическую input-цепочку, сохраняя доступ SSH. Учитывайте native
nftables наряду с iptables и Docker; не заменяйте firewall целиком.

На выходном узле включите `wg-quick@wg-private` и проверьте `ping -c 3 10.254.77.1`. Для ICMP-проверки при необходимости добавьте узкое разрешение ICMP на WG-интерфейсе; работоспособность SOCKS5 не требует разрешать весь input.

Контроль доступа должен быть явно настроен в firewall каждого узла.
Не дублируйте ограничения в PostUp/PostDown без проверки порядка правил.

## SOCKS5 на выходном узле

Установите sing-box 1.14.2 из [проверенного релиза](versions.md). Бинарник — `/usr/local/bin/sing-box`, root:root, `0755`.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin hy-exit
install -d -o root -g hy-exit -m 750 /etc/hysteria-exit
```

Если пользователь уже существует, не создавайте его повторно. Скопируйте [конфигурацию](../examples/hysteria-exit.json) в `/etc/hysteria-exit/config.json`, задайте случайный SOCKS-пароль локально. Этот же пароль понадобится серверу Hysteria. Проверьте интерфейс `ens1`. Права файла root:hy-exit `0640`.

```sh
/usr/local/bin/sing-box check -c /etc/hysteria-exit/config.json
```

Установите [unit](../examples/systemd/hysteria-exit.service) в `/etc/systemd/system/hysteria-exit.service`:

```sh
systemctl daemon-reload
systemctl enable --now hysteria-exit
systemctl status hysteria-exit --no-pager
ss -lntp
```

SOCKS слушает только `10.254.77.2:1080`, поддерживает TCP и UDP, требует пароль. UDP relay использует динамический порт, поэтому firewall разрешает UDP между приватными адресами партнёров, а не только UDP 1080. Приватные конечные назначения отклоняются.

Проверка с входного узла: handshake WG должен быть свежим; полный тест через Hysteria должен показывать ожидаемый адрес своего выхода. Не публикуйте пароль SOCKS в командной строке `curl --proxy-user`: используйте защищённый временный config-файл либо готовый клиент Hysteria.
