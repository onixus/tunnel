# Группы маршрутов устройств R-TrustTunnel

Серверная реализация принадлежит `tunnel`: `server/overlay/app/rtrust_profiles.py`,
шаблоны и статические файлы в том же каталоге, упаковка в `deploy/`, тесты в
`server/tests/`. В `R-Trusttunnel` остаются Rust codec, клиент получения политики
и применение маршрутов средствами ОС. Перенос не меняет клиентский API.

Это политика TUN настольных устройств. Переключение выходов Hysteria/TrustTunnel
продолжает работать через отдельный механизм [маршрутов сервисов](service-routing.md).

## Управление

Администратор открывает `/admin/agent-routes` по ссылке «Маршруты устройств» из
консоли. Используется существующая admin cookie; запись требует отдельного CSRF
токена. Администратор создаёт группы, редактирует CIDR IPv4, назначает активные
настольные устройства разных пользователей и выдаёт одноразовый код привязки от
имени активного пользователя. Доступ с device bearer token запрещён.

Назначенная администратором группа имеет приоритет над пользовательской.
Удаление группы или снятие назначения возвращает пользовательскую политику при
следующем запросе клиента. Политика содержит 1–16 include, 0–64 exclude и
`exclude_lan`; host bits и IPv6 отклоняются. Android/iOS не получают назначения
администратора через этот редактор. Редактирование/удаление группы проверяет
ревизию; назначение проверяет прежнюю группу, предотвращая потерю чужого изменения.

`GET /portal/v2/routing` доступен только действующему device token. Формат
остаётся `{"policy":null}` либо объект с `group`, `revision`, `include`,
`exclude`, `exclude_lan`. Ревизия пользовательской группы — `<id>:<revision>`,
административной — `admin:<id>:<revision>`. Админская страница показывает время
и ревизию последнего получения. Это не подтверждение применения на устройстве.
Клиент отвечает за безопасный переход политики и переподключение.

`/profiles` и `/portal/v2/route-groups` сохраняют пользовательское управление.
Отзыв устройства запрещает дальнейшие запросы и очищает обе принадлежности к
группам и запись получения. Уже скачанные VPN-пароли отзываются отдельно.

## Упаковка и миграция

```sh
python3 deploy/prepare-portal-update.py --base-image CURRENT_LOCAL_IMAGE --tag NEW_RELEASE_TAG
```

Сборщик принимает точный установленный портал/console image, сохраняет endpoint,
codec, routing adapter, entrypoint и mounts. В Docker build context попадают
только overlay и patcher. Новая ссылка и регистрация API добавляются идемпотентно.
Проверка запускается без сети и production mounts с временной БД; только после
успеха публикуется новый локальный tag. Работающие контейнеры не заменяются.
Базовый образ должен уже содержать `rtrust-codec` и cryptography.

Перед установкой новой версии оператор делает SQLite backup API и сохраняет
`.rtrust-profile-key`, Compose, точный прежний image ID и все routing mounts.
Новые таблицы добавляются при старте через `CREATE TABLE IF NOT EXISTS`.
Откат выполняется возвратом образа, без перезаписи БД старой копией.
Обновлять нужно портал, а console image — для новой ссылки в навигации.
Установку на production этот перенос не выполняет.

## Проверки

```sh
python3 -m venv /tmp/tunnel-portal-venv
/tmp/tunnel-portal-venv/bin/pip install -r server/test-environment/requirements.txt
# codec собирается в клиентском репозитории: cargo build -p rtrust-codec --locked
export RTRUST_CODEC=/absolute/path/to/rtrust-codec
/tmp/tunnel-portal-venv/bin/python -m unittest discover -s server/tests -p 'test_exchange.py'
/tmp/tunnel-portal-venv/bin/python -m unittest discover -s server/tests -p 'test_agent_routes.py'
python3 server/tests/test_publication.py
# При собранных Rust examples portal_e2e/routing_e2e в клиентском target:
/tmp/tunnel-portal-venv/bin/python server/tests/native_exchange.py
/tmp/tunnel-portal-venv/bin/python server/tests/routing_exchange.py
node --check server/overlay/app/static/rtrust-admin-routes.js
# Для browser E2E: pip install playwright pytest; python -m playwright install chromium
/tmp/tunnel-portal-venv/bin/python -m pytest -q server/tests/test_agent_routes_browser.py
```

Тесты используют синтетические учётные записи и временную SQLite. Кодек является
внешней клиентской зависимостью; тестам больше не нужен overlay из клиентского
репозитория. При наличии соседнего `R-Trusttunnel` используется его debug codec.

Перенесён базовый overlay из worktree `server-route-publication/R-Trusttunnel`
на commit `4400ca1`; административный API взят из его незакоммиченного
`rtrust_profiles.py` 6 октября 2026 и завершён здесь (страница, assets, проверки,
очистка назначения при отзыве). Исходный клиентский worktree не изменялся.
