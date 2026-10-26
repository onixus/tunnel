# Журнал закрытия сессий TrustTunnel endpoint

Официальный endpoint 1.1.0 на уровне INFO пишет только `Listening to TCP/UDP …`, поэтому обрыв клиентского туннеля не оставляет следа на сервере. [Патч](../patches/trusttunnel-endpoint-session-close-log.patch) к исходникам [TrustTunnel v1.1.0](https://github.com/TrustTunnel/TrustTunnel/tree/v1.1.0) добавляет запись о закрытии каждой клиентской сессии. Сейчас на сервере работает официальный бинарь без патча; чтобы получить журнал, нужно собрать endpoint самостоятельно (ниже) и заменить им `trusttunnel_endpoint` при сборке образа.

## Что пишется

При запуске:

```text
Session timeouts: client_listener_timeout=600s (closes h2/h3 sessions without new tunnel requests), quic_max_idle_timeout=600s (h3 sessions without packets are closed after the smaller of this and the client's value), tls_handshake_timeout=10s, tcp_connections_timeout=604800s, udp_connections_timeout=300s, tcp_keepalive=on (idle=7200s interval=75s probes=9)
```

`client_listener_timeout_secs` (в `vpn.toml` панели — 600) одновременно:

- закрывает сессию h2/h3, если за это время клиент не открыл ни одного нового соединения в туннеле, даже когда старые соединения ещё передают данные;
- задаёт серверный QUIC `max_idle_timeout`. Действует меньшее из серверного и клиентского значений (RFC 9000, §10.1); клиент R-TrustTunnel объявляет 30 с и шлёт QUIC keepalive каждые 10 с, поэтому `quic_idle_timeout after=30s` означает, что от клиента 30 с не доходило ни одного пакета.

При закрытии сессии, которая прошла аутентификацию, пример синтетический:

```text
[CLIENT=812 TUN=37] Session closed: sid=7f3a9c21 proto=h3 user=u:1a2b3c4d duration=1834.2s reason=quic_idle_timeout after=30s bytes_up=1048576 bytes_down=73400320 streams=412 auth_failures=0
```

| Поле | Значение |
| --- | --- |
| `[CLIENT=… TUN=…]` | порядковые номера соединения и туннеля endpoint, те же, что в debug-журнале |
| `sid` | случайный 32-битный id сессии |
| `proto` | `h2` (HTTP/2 по TCP), `h3` (HTTP/3 по QUIC) или `h1` (HTTP/1.1 CONNECT, если клиент выбрал его) |
| `user` | `u:` + первые 4 байта HMAC-SHA256 имени пользователя; `-`, если имя неизвестно |
| `duration` | время от начала туннеля до закрытия |
| `reason` и детали | см. ниже |
| `bytes_up` / `bytes_down` | байты полезной нагрузки клиент→сеть / сеть→клиент |
| `streams` | число запросов (соединений) в туннеле |
| `auth_failures` | отклонённые запросы: так видны учётные данные, отозванные во время сессии |

IP-адрес клиента и учётные данные в строку не попадают. Тег `user` ставится только после успешной аутентификации; ключ HMAC случайный и создаётся при каждом запуске endpoint, нигде не сохраняется и не пишется. Поэтому тег нельзя восстановить перебором имён, и он одинаков для пользователя только в пределах одного запуска: после рестарта у того же пользователя другой тег.

Сессия считается аутентифицированной, как только первый запрос с верными учётными данными принят в туннель, ещё до его обработки, поэтому короткие сессии легитимных клиентов не теряются. Сессии, которые так и не прошли аутентификацию (сканеры, неверные учётные данные, соединения без единого запроса), отдельными строками не пишутся. Раз в минуту, если такие были, выводится одна сводка:

```text
Unauthenticated sessions closed: 1000 (auth_rejected=750 closed_by_peer=250)
```

## Причины

| `reason` | Детали | Когда |
| --- | --- | --- |
| `closed_by_peer` | `code=` если клиент прислал код (GOAWAY/CONNECTION_CLOSE NO_ERROR) | клиент штатно закрыл соединение (EOF, GOAWAY, CONNECTION_CLOSE без ошибки) |
| `reset_by_peer` | — | TCP RST, обрыв записи (ECONNRESET, EPIPE, ECONNABORTED) |
| `idle_timeout` | `after=600s` | нет новых запросов в туннеле за `client_listener_timeout` |
| `quic_idle_timeout` | `after=` эффективный таймаут | от клиента не было QUIC-пакетов за min(серверный, клиентский `max_idle_timeout`) |
| `keepalive_timeout` | — | TCP ETIMEDOUT: нет ответа на keepalive или повторные передачи |
| `tls_error` | `by=client code=` — TLS alert от клиента; `by=server` — ошибку TLS обнаружил сервер; для QUIC `code=` 0x100–0x1ff | ошибка TLS |
| `protocol_error` | `by=client/server code=0x… [app]` | HTTP/2 GOAWAY или QUIC CONNECTION_CLOSE с кодом ошибки; `app` — код уровня приложения (HTTP/3) |
| `auth_rejected` | `detail="credentials rejected"` или `"connection limit"` | SNI-учётные данные отклонены или превышен лимит соединений |
| `internal_error` | — | библиотека HTTP/2 вернула ошибку без кода протокола и без ошибки ввода-вывода |
| `aborted` | — | задача сессии завершилась без причины (паника, отмена) |
| `io_error` | `kind=` | прочие ошибки ввода-вывода, в том числе `InvalidData` не от TLS |

## Остановка

При остановке endpoint отдельные сессии не пишутся, вместо них одна строка: `Shutdown (SIGTERM): N sessions closed` (или `SIGINT`). Если с последней минутной сводки закрывались неаутентифицированные сессии, их сводка добавляется в ту же строку: `Shutdown (SIGTERM): 3 sessions closed; Unauthenticated sessions closed: 2 (reset_by_peer=2)`.

SIGTERM, который шлёт супервизор панели, принимает отдельный поток, не зависящий от async runtime: он пишет строку, сбрасывает буфер журнала (в том числе `--log_file`) и завершает процесс тем же SIGTERM с действием по умолчанию. Процесс завершается, даже если запись не удалась: при панике (например, stdout закрыт) — сразу, а если запись зависла (stdout-pipe никто не читает) — через 3 с, без сводки. Для родителя статус выхода такой же, как без патча (процесс завершён сигналом), только перед этим появляется сводка. При `docker restart` endpoint получает SIGKILL вместе с контейнером, и сводки нет.

## Сборка

Нужны Rust через rustup (версию задаёт `rust-toolchain.toml` upstream, сейчас 1.95) и, как в upstream Dockerfile, `build-essential cmake git libclang-dev` — BoringSSL для QUIC собирается из исходников. Собирать на Linux x86_64 (или в контейнере), чтобы бинарь подошёл образу:

```sh
git clone --branch v1.1.0 https://github.com/TrustTunnel/TrustTunnel.git
cd TrustTunnel
git apply --check /абсолютный/путь/к/patches/trusttunnel-endpoint-session-close-log.patch
git apply /абсолютный/путь/к/patches/trusttunnel-endpoint-session-close-log.patch
cargo test -p trusttunnel --lib --test sigterm
cargo build --release --bin trusttunnel_endpoint
```

Бинарь: `target/release/trusttunnel_endpoint`. Он подменяет официальный при сборке образа по [инструкции](trusttunnel-server.md#подготовить-исходники-и-образ); в [versions](versions.md) нужно записать SHA256 собственной сборки вместо официального архива. Логи смотреть `docker logs trusttunnel-web | grep -E 'Session (closed|timeouts)|Unauthenticated sessions|Shutdown'`.
