# Отдельные credentials устройств и отзыв на endpoint

Issue [#22](https://github.com/onixus/tunnel/issues/22), клиентская интеграция
[эпик #30 / #35](https://github.com/onixus/Rust-trustvpn/issues/35).
Серверная реализация — `server/overlay/app/rtrust_credentials.py` и v2 API.

## Поддерживаемая граница

Только локальный TrustTunnel endpoint под единственным supervisor портала:
HTTP/2 и HTTP/3 (QUIC). Hysteria, AmneziaWG, импортированные внешние профили и
legacy/shared credentials не получают обещание managed revocation.
Администратор установки включает выдачу через `RTRUST_MANAGED_CREDENTIALS=1`.
По умолчанию новая выдача выключена; отзыв уже выданных device credentials и
повтор незавершённых операций продолжают работать даже после отключения выдачи.

Устройство принадлежит пользователю. В таблице `rtrust_credentials` оно связано
с одним `configs.id` локального endpoint и номером поколения. Username случайный
и уникальный; пароль содержит 32 случайных байта. Ротация меняет пароль этого
конфига. Нельзя выдать device credential соседнему устройству, даже того же
пользователя. Старые v1 device-owned configs при миграции отзываются; общие
configs с `device_id IS NULL` сохраняются. Их ранее скачанные пароли остаются
действующими: интерфейс явно предупреждает об этой границе.

## Контракт API

Все ответы `/portal/v2/` имеют `Cache-Control: no-store`; ошибки тоже.
Секреты не входят в ответы состояния и аудит. Password хранится в существующем
configs, необходимом endpoint; `credentials.toml` заменяется атомарно с правами
0600. Доступ к базе, каталогу данных и резервным копиям остаётся административным.

| Метод | Путь | Авторизация и результат |
|---|---|---|
| GET | `/portal/v2/capabilities` | Публичная информация: `managed_credentials`, включение, протоколы, политика сессий, предел применения и повтор |
| GET | `/portal/v2/device-credentials` | Cookie пользователя; состояния его устройств, включая отозванные, последние 20 операций |
| POST | `/portal/v2/devices/{id}/credentials/provision` | Cookie + CSRF; `Idempotency-Key`: canonical UUID; отдельный credential и grant его профиля |
| POST | `/portal/v2/devices/{id}/credentials/rotate` | Те же требования; новое поколение и пароль |
| DELETE | `/portal/v2/devices/{id}` | Cookie + CSRF; отзыв portal token, grants, маршрутов и **всех** device-owned configs; состояние применения в `credentials` |
| POST | `/portal/v2/devices/{id}/credentials-retry` | Cookie + CSRF; повтор применения записанного желаемого состояния, включая отозванное устройство |
| POST | `/portal/v2/device-token/renew` | Ещё действующий Bearer token; атомарная замена на новый сроком 30 суток |

Повтор provision/rotate с тем же UUID не меняет поколение и пароль; UUID нельзя
переиспользовать для другого устройства или действия. Ответ показывает текущее
состояние устройства, поэтому после последующих действий это не снимок первого
ответа. DELETE повторно использует операцию revoke. Конкурирующие rotate/revoke
сериализованы; отозванное устройство нельзя оживить ротацией. Межпользовательский
доступ возвращает 404. Устройство не может управлять credentials через Bearer.
Старый клиентский кабинет использует тот же durable отзыв через интеграцию
`db.revoke_device`. Административная sidecar-консоль вызывает
`POST /admin/api/device-credentials/{id}/revoke` на портале с admin cookie и CSRF,
проверяет состояние revoke и показывает ошибку при pending/failed. Она не запускает
endpoint. Общие операции rotate/revoke ключа не могут обойти lifecycle device key.
Роль администратора проверяет API портала.

Привязка остаётся одноразовой: код живёт 180 секунд, его hash потребляется в
транзакции вместе с созданием устройства. QR/code не содержит server admin secret.
Portal token живёт 30 суток; renewal потребляет старый token. Просроченный token
требует новой привязки через браузер; offline renewal невозможен. Без портала
скачанный VPN-пароль работает до фактического отзыва на endpoint.

## Применение, рестарт и политика сессий

Операция сначала сохраняется как `requested`, затем `pending`. Применение
пересобирает полный набор действующих credentials и перезапускает процесс, только
если этот набор отличается от загруженного работающим endpoint (см. «Применение
конфигурации без рестарта» ниже): provision из резерва применяется без рестарта,
rotate и revoke всегда перезапускают процесс. В пределах 15-секундного окна ожидается готовность нового локального TCP listener;
после двух секунд непрерывной готовности и живого процесса записывается `applied`; отсутствие сертификата/процесса или исключение даёт `failed` с
`endpoint_unavailable`. Это подтверждение применения локальным supervisor,
а не результат клиентской диагностики сети. История applied не является текущим
healthcheck. Ошибки не сохраняют exception text или secrets.

При настроенном и здоровом endpoint целевой предел применения — 15 секунд
(проверяемый bound изолированной приёмки, не гарантия при конкуренции за SQLite): до 10 секунд
на завершение старого процесса, до одной секунды на reap после kill; оставшееся время используется
для ожидания старта и двух секунд наблюдения готового нового процесса. Пропавшие сертификаты не запускают долгий certbot
под блокировкой применения. Во время outage верхнего предела успешного отзыва
нет: состояние остаётся failed/pending. После рестарта портала операции повторяются;
фоновая попытка начинается каждые 5 секунд после окончания предыдущей. Устаревшая
неприменённая ротация помечается `superseded_by_revoke`, не ложным applied.

Политика активных сессий — **restart_all**: все серверные сессии завершаются.
Другие устройства сохраняют свои пароли и переподключаются. HTTP/3 клиентский
сокет может ожидать своего таймаута вместо немедленного EOF; сервер больше не
передаёт его трафик. Бесшовность соседних активных соединений не поддерживается.

Один процесс портала обязателен: эксклюзивная файловая блокировка захватывается
до старта upstream supervisor, второй worker завершается с ошибкой. Порядок
блокировок supervisor → SQLite; `BEGIN IMMEDIATE` защищает желаемое состояние
во время применения. Повтор перезапускает процесс, если предыдущая попытка уже
записала файл, но не успела применить его: супервизор сравнивает файлы с тем,
что загрузил текущий процесс, а не с прошлой записью.

## Применение конфигурации без рестарта

Официальный endpoint 1.1.0 по SIGHUP перечитывает только `hosts.toml`
(TLS-хосты, сертификат); `vpn.toml`, `rules.toml` и `credentials.toml` читаются
только при старте. Поэтому супервизор (`server/upstream/app/endpoint.py`):

- запоминает содержимое `vpn.toml`, `rules.toml`, `credentials.toml`, с которым
  стартовал процесс, и перезапускает его только при их фактическом изменении;
  повторные одинаковые сохранения ничего не перезапускают;
- держит в endpoint резерв из `ENDPOINT_STANDBY_CREDENTIALS` (по умолчанию 16)
  случайных никому не выданных credentials (таблица `endpoint_standby`, пароль —
  32 случайных байта). Новый конфиг (кабинет, админка, устройство, managed
  provision) забирает резервный cred в той же транзакции; `credentials.toml` —
  отсортированное объединение выданных и резервных, поэтому его содержимое не
  меняется и рестарта нет. При каждом неизбежном рестарте невыданный резерв
  целиком заменяется новым; если он исчерпан, выдача вызывает один рестарт с
  новым резервом. Сбой замены резерва не отменяет рестарт: файл без отозванных
  кредов к этому моменту уже записан;
- схлопывает рестарты от кабинета/админки/консоли: ждёт 1 с тишины, не чаще раза
  в 5 с, не позже 8 с от первого запроса даже при непрерывном потоке запросов;
  вызов возвращается после применения. Ошибка рестарта возвращается вызывающему
  (HTTP 500), рестарт повторяется не чаще раза в 5 с; ожидание ограничено 60 с
  (`TimeoutError`). Раз в 60 с вотчер сертификата сверяет процесс с файлами и
  перезапускает упавший или не получивший изменения endpoint;
- managed-операции (`apply_pending`) применяются сразу под блокировкой супервизора;
  резерв обновляется в их транзакции-fence, а не во втором пишущем соединении.

| Изменение | Применение |
|---|---|
| Новый конфиг/устройство, managed provision (резерв не пуст) | на лету, без рестарта |
| Повтор без изменений (конфиг, настройки, retry) | ничего |
| Домен подключения, `conn_sni`, обновление сертификата | SIGHUP, сессии живут |
| Адрес/протокол/`show_*`/SMTP/бренд и прочие настройки, которых нет в файлах endpoint | ничего |
| Отзыв/удаление конфига, блокировка/удаление пользователя, rotate, revoke устройства | рестарт (fail-closed): все сессии закрываются, отозванный cred не принимается |
| Порт (`conn_port`), шаблон `vpn.toml`, `rules.toml` | рестарт |
| Выдача при пустом резерве, возврат пользователя из блокировки | рестарт |
| Нет домена/сертификата | endpoint останавливается |

Закрыть сессии только отозванного пользователя без рестарта официальный
endpoint не умеет: это требует доработки самого endpoint.

Модель угроз резерва. Резервные пары — действующие credentials без владельца:
открытым текстом в SQLite (как и выданные пароли, которых требует
`credentials.toml`) и в `credentials.toml` (оверлей пишет его с правами 0600). Их нет в ответах API,
админке и логах; блокировка и отзыв пользователей их не затрагивают. Утечка базы,
каталога данных или резервной копии раскрывает их наравне с выданными паролями,
поэтому доступ к ним остаётся административным. Время жизни пары — до ближайшего
рестарта endpoint (замена резерва). Немедленно аннулировать резерв:
`ENDPOINT_STANDBY_CREDENTIALS=0` и любое действие, требующее рестарта, либо
рестарт портала; после этого `credentials.toml` содержит только выданные
credentials, а новые выдачи снова требуют рестарта.

Изменение живёт в `server/upstream/app/endpoint.py` и `db.py`; аддитивный образ
`deploy/prepare-portal-update.py` их не переносит, нужна пересборка базового
образа портала. Оверлей проверяет контракт (`SUPERVISOR_CONTRACT = 2`,
`db.claim_credential`): сборка аддитивного образа на старой базе прерывается в
`apply-design-system.py`, а портал со старой базой не стартует
(`rtrust_credentials.require_supervisor`), иначе managed revoke был бы fail-open.
Тесты: `server/tests/test_endpoint_reload.py` (супервизор),
`server/tests/test_endpoint_reload_overlay.py` (overlay `install()` + `apply_pending`).

## Приёмка и rollout

12.10.2026: изолированный официальный endpoint 1.1.0 linux-aarch64 проверен
через Rust `rtrust-inspect` отдельно по HTTP/2 и HTTP/3 с профилем,
скачанным через API экспорта. Настроенный `CLIENT_CA_FILE` переносится в
managed profile; недоступный trust file возвращает 503 вместо неполного профиля. Два разных device
credentials подключаются; после rotate старый пароль отклонён; после DELETE
сохранённый пароль отклонён без portal API; активная серверная сессия завершена;
соседнее устройство переподключается. Применение рестарта около 2–3 секунд;
наблюдение клиентского HTTP/3 socket timeout увеличивает тест до около 5–6 секунд.
Официальный архив SHA256:
`c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686`.

В CI используется x86_64 архив 1.1.0 с закреплённой checksum из `docs/versions.md`
и клиент из закреплённого commit существующего device-routing workflow.
Тест `server/tests/managed_credentials_acceptance.py` запускает только disposable
Docker endpoint с синтетическими accounts. Private connections разрешены только
в тестовом шаблоне для локальных echo/HTTP targets; рабочий шаблон не меняется.
Регрессии проверяют concurrency, idempotency, outage/retry, SQLite schema restart,
изоляцию владельцев, secret-free audit, renewal и права файла. Browser checks
проверяют видимый failed и возможность повторить отзыв на desktop/mobile.

Для rollout: сохранить image ID и согласованную защищённую копию данных,
собрать additive overlay через `deploy/prepare-portal-update.py` для портала и,
если установлена, отдельной sidecar-консоли; отдельно проверить
candidate, затем заменить образ в согласованное окно рестарта и включить env.
Живая установка этой реализацией не менялась. Отключение env запрещает новую
выдачу, но не отменяет уже сохранённые отзывы. Откат образа не должен восстанавливать
старую базу: это вернёт отозванные пароли. Клиент issue #35 остаётся отдельным.

## Profile origin label

`GET /portal/v2/profiles` returns `origin` for every item as a fixed label, not an
authentication claim: `portal_managed` (account-managed config) or
`external_stored` (user import). A label is 1–80 printable ASCII bytes
(0x20–0x7E) and clients compare it byte-wise. Android and iOS reject the whole
managed batch on any other value; a missing or `null` origin means an unknown
source. New labels must stay within this alphabet and are declared in
`ORIGIN_LABELS` in `server/overlay/app/rtrust_profiles.py`, which
`test_profile_origin_labels_follow_client_contract` checks.

## Client profile limit

Android and iOS reject a whole managed batch with more than 64 profiles. Clients
sync only with a device token, so the server caps each device's sync set at
`MAX_CLIENT_PROFILES = 64` (`server/overlay/app/rtrust_profiles.py`, advertised
as `max_client_profiles` in `/portal/v2/capabilities`). The set is the device's
live grants; grants to revoked profiles or configs do not count.

- Growing a device set beyond 64 is refused with HTTP 409
  `Device profile limit reached (64)` and no partial write: a new grant to a
  full device, an import committed by a full device (it would be granted to
  that device), and managed credential provisioning that would add a 65th grant
  (the transaction, including migration of v1 device configs, rolls back).
  Re-granting an existing grant stays idempotent.
- A historical device set above the limit is never truncated:
  `GET /portal/v2/profiles` and `POST /portal/v2/snapshot` with a device token
  return HTTP 409 `{"detail":"Too many profiles for client sync"}`. A truncated
  list would make clients delete the omitted managed profiles. Android, iOS and
  the desktop client treat any non-200 as a failed sync and keep their last
  applied set. Remediation: the owner revokes grants until the device has at
  most 64 (revoked or deleted profiles included, see below).
- The owner browser view (session login, no device token) is a management
  view, not a client sync: it is unaffected by this limit and keeps its
  previous bounds (up to 100 stored imports plus 100 account configs). Owner
  imports keep the previous cap of 100 stored profiles; account configs are not
  counted there.
- Device checks scan at most `MAX_DEVICE_GRANT_SCAN = 1000` raw grant rows;
  reaching that bound is the same explicit 409, never a truncated set.
- Grants do not outlive their managed config. Every overlay path that revokes
  a config (device revocation, legacy `revoke_device`, migration of v1 device
  configs on provisioning, rotation of extra device configs), the console
  shared-key revoke (`trusttunnel.revoke`) and the upstream admin hard delete
  (`db.delete_config`, wrapped by the overlay) remove the config's `managed-N`
  grants in the same transaction. Startup (`init()`) runs an idempotent,
  transactional sweep of grants to revoked or deleted configs left by earlier
  versions; grants a device can still read are never removed.
- A managed profile id is only the canonical `managed-N` (`N` a positive
  decimal SQLite integer without sign, padding or separators). Variants such
  as `managed-01` or `managed-+1` name no profile (`404` on grant, ignored on
  read); historical rows with such ids are removed by the startup sweep.
  Revoked stored imports keep the existing behaviour (owner delete already
  removes their grants).
- `POST /portal/v2/profiles/{id}/grants` with `allow:false` only needs a live
  device of the caller: it removes a grant even when the profile is revoked,
  deleted or never existed, and answers `200 {"updated":true}` in all those
  cases, so it neither fails nor reveals whether another owner's profile
  exists. Another owner's device is still `404 Device not found`. Removing a
  grant that does not exist is a no-op and is not audited. `allow:true` still
  requires an accessible profile.
- Capacity check and grant insert share one `BEGIN IMMEDIATE` transaction, so
  concurrent grants cannot push a device past the limit.
- Error bodies carry no profile, device or credential identifiers.

## Atomic snapshot and offline freshness

The paired client requests an authenticated, transactionally frozen snapshot
with explicit `include_secrets: true`. Capabilities advertise `snapshot: 1`
and `offline_freshness: 1`; `freshness_version: 1` adds the finite receipt.
The receipt age is limited by `RTRUST_OFFLINE_MAX_AGE_SECONDS` (default 86400,
range 60–86400) and the token lifetime at the end of the transaction.
Unnegotiated snapshots retain their original body shape. Invalid configuration
or expired access refuses the whole snapshot. Clients anchor TTL before the
request; Android additionally binds the encrypted receipt to boot count and
elapsed realtime. No LAN, boot or diagnostic evidence is uploaded.

This bounds cached managed admission, independently of endpoint revocation.
It does not revoke independently owned exports or protect against a root owner.
QR invitations require the same HTTPS browser origin and expire after three
minutes. The additional paired-client `/token/renew` consent keeps its existing token
and extends only a still-active portal
token; it does not change endpoint credentials. Existing managed credential
issuance, rotation, revocation and its single endpoint owner remain unchanged.
