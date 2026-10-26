# Журнал закрытия сессий TrustTunnel endpoint

Официальный endpoint 1.1.0 на уровне INFO пишет только `Listening to TCP/UDP …`, поэтому обрыв клиентского туннеля не оставляет следа на сервере. [Патч](../patches/trusttunnel-endpoint-session-close-log.patch) к исходникам [TrustTunnel v1.1.0](https://github.com/TrustTunnel/TrustTunnel/tree/v1.1.0) добавляет запись о закрытии каждой клиентской сессии. Сейчас на сервере работает официальный бинарь без патча; чтобы получить журнал, нужно собрать endpoint самостоятельно (ниже) и заменить им `trusttunnel_endpoint` при сборке образа.

## Что пишется

При запуске, после `Listening to …`:

```text
Session timeouts: client_listener_timeout=600s (closes h2/h3 sessions without new tunnel requests; also QUIC max_idle_timeout, closes h3 sessions without packets), tls_handshake_timeout=10s, tcp_connections_timeout=604800s, udp_connections_timeout=300s, tcp_keepalive=on (idle=7200s interval=75s probes=9)
```

`client_listener_timeout_secs` (в `vpn.toml` панели — 600) одновременно:

- закрывает сессию h2/h3, если за это время клиент не открыл ни одного нового соединения в туннеле, даже когда старые соединения ещё передают данные;
- задаёт QUIC `max_idle_timeout`: сервер закрывает QUIC-соединение, от которого столько времени не приходило пакетов.

При закрытии каждой сессии HTTP/2 (TCP) или HTTP/3 (QUIC), пример синтетический:

```text
[CLIENT=812 TUN=37] Session closed: sid=7f3a9c21 proto=h3 user=u:1a2b3c4d duration=1834.2s reason=quic_idle_timeout after=600s bytes_up=1048576 bytes_down=73400320 streams=412 auth_failures=0
```

| Поле | Значение |
| --- | --- |
| `[CLIENT=… TUN=…]` | порядковые номера соединения и туннеля endpoint, те же, что в debug-журнале |
| `sid` | случайный 32-битный id сессии |
| `proto` | `h2` (TCP) или `h3` (QUIC) |
| `user` | `u:` + первые 4 байта SHA-256 имени пользователя; `-`, если имя неизвестно |
| `duration` | время от начала туннеля до закрытия |
| `reason` и детали | см. ниже |
| `bytes_up` / `bytes_down` | байты полезной нагрузки клиент→сеть / сеть→клиент |
| `streams` | число запросов (соединений) в туннеле |
| `auth_failures` | отклонённые запросы: так видны учётные данные, отозванные во время сессии |

IP-адрес клиента и учётные данные в строку не попадают. Тег пользователя проверяется так: `printf '%s' 'имя' | sha256sum | cut -c1-8`.

## Причины

| `reason` | Детали | Когда |
| --- | --- | --- |
| `closed_by_peer` | `code=` если клиент прислал код (GOAWAY/CONNECTION_CLOSE NO_ERROR) | клиент штатно закрыл соединение (EOF, GOAWAY, CONNECTION_CLOSE без ошибки) |
| `reset_by_peer` | — | TCP RST, обрыв записи (ECONNRESET, EPIPE, ECONNABORTED) |
| `idle_timeout` | `after=600s` | нет новых запросов в туннеле за `client_listener_timeout` |
| `quic_idle_timeout` | `after=600s` | от клиента не было QUIC-пакетов за `max_idle_timeout` |
| `keepalive_timeout` | — | TCP ETIMEDOUT: нет ответа на keepalive или повторные передачи |
| `tls_error` | `by=client/server`, `code=` для QUIC crypto 0x100–0x1ff | ошибка TLS |
| `protocol_error` | `by=client/server code=0x… [app]` | HTTP/2 GOAWAY или QUIC CONNECTION_CLOSE с кодом ошибки; `app` — код уровня приложения (HTTP/3) |
| `auth_rejected` | `detail="credentials rejected"` или `"connection limit"` | SNI-учётные данные отклонены или превышен лимит соединений |
| `io_error` | `kind=` | прочие ошибки ввода-вывода |

При остановке endpoint отдельные сессии не пишутся, вместо них одна строка: `Shutdown (SIGTERM): N sessions closed` (или `SIGINT`). Без патча SIGTERM от супервизора панели завершал процесс без записи; теперь endpoint пишет сводку и сразу выходит с кодом 143, как и раньше, без мягкой остановки. При `docker restart` endpoint получает SIGKILL вместе с контейнером, и сводки нет.

## Сборка

Нужны Rust через rustup (версию задаёт `rust-toolchain.toml` upstream, сейчас 1.95) и, как в upstream Dockerfile, `build-essential cmake git libclang-dev` — BoringSSL для QUIC собирается из исходников. Собирать на Linux x86_64 (или в контейнере), чтобы бинарь подошёл образу:

```sh
git clone --branch v1.1.0 https://github.com/TrustTunnel/TrustTunnel.git
cd TrustTunnel
git apply --check /абсолютный/путь/к/patches/trusttunnel-endpoint-session-close-log.patch
git apply /абсолютный/путь/к/patches/trusttunnel-endpoint-session-close-log.patch
cargo test -p trusttunnel --lib session_log
cargo build --release --bin trusttunnel_endpoint
```

Бинарь: `target/release/trusttunnel_endpoint`. Он подменяет официальный при сборке образа по [инструкции](trusttunnel-server.md#подготовить-исходники-и-образ); в [versions](versions.md) нужно записать SHA256 собственной сборки вместо официального архива. Логи смотреть `docker logs trusttunnel-web | grep -E 'Session (closed|timeouts)|Shutdown'`.
