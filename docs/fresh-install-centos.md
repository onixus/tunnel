# Установка на CentOS Stream

Мастер предназначен для **чистых CentOS Stream 9 и 10 x86_64** с systemd.
Рекомендуется Stream 10; его ОС требует процессор x86-64-v3. CentOS Linux 7/8
и Stream 8 мастер отклоняет. Нужны root/sudo, 4 ГБ RAM, 2 CPU, 15 ГБ свободного
места, `/dev/net/tun` и Интернет для CentOS, Docker Hub, PyPI, crates.io и GitHub.
На CentOS Stream 9 агент использует отдельный Python 3.12; системный Python не заменяется.
Интеграционный стенд этой сборки — Stream 10 с Enforcing SELinux. Для Stream 9
проверены выбор ОС и зависимости; полного VM-прогона Stream 9 не было.

1. Перенесите на сервер `tunnel-installer-centos-stream-amd64.run` и `.run.sha256`.
2. Выполните:

   ```sh
   sha256sum -c tunnel-installer-centos-stream-amd64.run.sha256
   sudo bash tunnel-installer-centos-stream-amd64.run
   ```

3. Укажите публичный IPv4/домен и e-mail администратора. Если SSH работает не на 22,
   добавьте `--ssh-port ВАШ_ПОРТ`. Пароль генерируется автоматически.
4. После окончания прочитайте данные доступа:

   ```sh
   sudo cat /opt/tunnel-installer/access.json
   ```

5. На своём компьютере выполните SSH-команду из файла, затем откройте
   **https://localhost:18443/admin/login**. Для входа другим SSH-пользователем замените
   `root` в команде. Сверьте отпечаток самоподписанного сертификата с `access.json`.
6. В панели: **Протоколы → Проверить обновления → Установить**. После установки
   создайте пользователя и выдайте конфигурацию.

Мастер устанавливает Docker CE из официального RPM-репозитория, предварительно
проверив отпечаток его ключа. Разрешает текущий SSH-порт, TrustTunnel 8443 TCP/UDP,
Hysteria 443 UDP и AmneziaWG 47443 UDP. Создаёт постоянную и активную policy firewalld,
блокирующую TCP 8081 из всех сетевых зон, включая trusted/docker.

SELinux не отключается. Для shared volumes задаются постоянные метки
`container_file_t`; агент, его Unix socket, конфигурации протоколов и сертификаты
получают нужные метки перед использованием. Если SELinux включён в ОС, он также
включается для Docker. Никакие существующие Podman/Docker пакеты принудительно не удаляются.
Для контейнера консоли устанавливается отдельный SELinux-домен `vpn_console_t`
с обычными ограничениями контейнера и разрешением подключения к Unix-сокету агента.
Остальные контейнеры этого разрешения не получают.
AmneziaWG получает домен `vpn_amnezia_t` с сетевыми правами и наблюдением
за управляющим Unix-сокетом. Глобальные SELinux booleans не меняются.

HTTPS-панель публикуется на loopback. Docker может публиковать VPN-порты независимо
от обычных правил firewalld: дополнительно используйте firewall хостинга.

**Hysteria** устанавливает H UI и выключенное ядро: сертификат/выходы/конфигурацию
настройте в H UI через SSH-туннель на порт 8081; пароль — `/root/h-ui-bootstrap.json`.
**CDN** требует собственного домена, настройки CDN и ограничения выбранного origin-порта.
Подробнее: [общая инструкция](fresh-install.md) и [протоколы](protocols.md).
Сертификат действует 365 дней, автоматического продления нет.

При сбое исправьте указанную причину и выполните:

```sh
sudo bash tunnel-installer-centos-stream-amd64.run --resume
```

Настройки и ключи сохраняются; установка поверх существующего сервера обычным
запуском отклоняется. Не удаляйте `/opt/tunnel-installer` для обхода этой проверки.
На минимальном cloud-образе могут отсутствовать сетевые модули работающего ядра.
Мастер попробует установить точную версию. Если она уже недоступна в репозитории,
он установит новое ядро и попросит выполнить `sudo reboot`, затем тот же `--resume`.
Автоматической перезагрузки нет.
При ошибке установки протокола проверьте root-журналы
`/opt/vpn-console/protocols/last-build.log` и `last-startup.log`.
После исправления причины повторите задание в панели.

Сборка из рабочей копии:

```sh
python3 scripts/build-installer.py --target centos-stream --client-source /путь/к/R-Trusttunnel
```

Основания: [Docker для CentOS](https://docs.docker.com/engine/install/centos/),
[версии CentOS](https://www.centos.org/cl-vs-cs/),
[firewalld policies](https://firewalld.org/documentation/man-pages/firewalld.policies.html).
