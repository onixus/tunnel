# Агенты tunnel

Серверные изменения живут здесь. Клиент — `onixus/Rust-trustvpn`; его логику не дублировать.

## Обновление TrustTunnel endpoint

Официальный endpoint нельзя ставить как есть. В v1.1.0 и v1.3.1 есть баг: живая HTTP/3-сессия завершается по `client_listener_timeout` (600 с без нового запроса), QUIC-соединение остаётся в мультиплексоре, а следующий keepalive закрывается кодом `0x42`. Клиент видит `quic_close layer=transport code=66 by=peer` и переподключается.

Перед каждой сборкой или обновлением endpoint применяй журнал, затем патч удержания сессии, и проверяй, что оба легли. Если upstream сдвинул контекст, перенеси смысл, не выбрасывай патч. Если upstream сдвинул контекст, перенеси смысл, не выбрасывай патч.

1. `patches/trusttunnel-endpoint-session-close-log.patch` — журнал закрытия сессий.
2. `patches/trusttunnel-h3-session-keep.patch` — только после журнала, не на чистый тег. HTTP/3 не рвётся таймером отсутствия новых запросов; если listen завершился без закрытия QUIC, задача поднимается заново (`quic_session_restart`). Закрытый канал не получает `CONNECTION_CLOSE` (`quic_session_kept`). `0x42` остаётся только для настоящей ошибки `recv`, и в кадр уходит фиксированная фраза.

```sh
git clone --branch <тег> https://github.com/TrustTunnel/TrustTunnel.git
cd TrustTunnel
git apply --check /абсолютный/путь/patches/trusttunnel-endpoint-session-close-log.patch
git apply /абсолютный/путь/patches/trusttunnel-endpoint-session-close-log.patch
git apply --check /абсолютный/путь/patches/trusttunnel-h3-session-keep.patch
git apply /абсолютный/путь/patches/trusttunnel-h3-session-keep.patch
```

Сборка — Linux x86_64. После замены бинарника проверь, что в нём есть `quic_session_kept`. Боевой файл: `/opt/trusttunnel-web/trusttunnel_endpoint.monitor`, он смонтирован в контейнер `trusttunnel-web` как `/opt/trusttunnel/trusttunnel_endpoint`. Перезапись файла без пересоздания контейнера не подхватывается: процесс держит старый inode.

Не откатывай эти патчи ради совпадения с официальным SHA. Не логируй адреса, имена пользователей и сырой текст ошибок. Не возвращай `patches/trusttunnel-endpoint-quic-close-monitor.patch`: он закрывает тот же канал кодом `0x42`.
