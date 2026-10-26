# Версии и источники

Зафиксировано 28.09.2026. Это закреплённые примеры версий и контрольных сумм, не обещание «последняя версия» на дату чтения.

| Компонент | Версия / источник | SHA256 linux x86_64 артефакта |
|---|---|---|
| Hysteria | [2.12.3](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.12.3), `hysteria-linux-amd64` | `8c7a68a906998b747a0db87586e364f995fbfddb95693ae6e2fdb68a6e920d3e` |
| H UI | [0.0.25](https://github.com/jonssonyan/h-ui/releases/tag/v0.0.25), `h-ui-linux-amd64` | `900ed683b3a3af3a79e5bdcc691b9f3db82f1758545f0f603f8bdecd9d1cd7ee` |
| sing-box | [1.14.2](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2), `sing-box-1.14.2-linux-amd64.tar.gz` | `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` |
| TrustTunnel endpoint | [1.1.0](https://github.com/TrustTunnel/TrustTunnel/releases/tag/v1.1.0), `trusttunnel-v1.1.0-linux-x86_64.tar.gz` | `91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7` |
| TrustTunnel Client | [1.1.7](https://github.com/TrustTunnel/TrustTunnelClient/releases/tag/v1.1.7), `trusttunnel_client-v1.1.7-linux-x86_64.tar.gz` | `791f00819e0242b2c38a04bb1403c30aa32701efbcdb059fbc3a6793ff0a45b5` |

AmneziaWG 3.1 собирается консолью из исходников [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) и [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) по тегам `v3.1.*`; локально проверены `v3.1.20260828` (commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`) и tools `v3.1.20260812` (commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`). Установленная версия видна в разделе [«Протоколы»](protocols.md).

Панель [Ttolyanich/trusttunnel-web](https://github.com/Ttolyanich/trusttunnel-web) закреплена на commit `fd8c6efae205e3d3a77b5ae3a632b46a702cc661`; поверх него применяется [локальный patch](../patches/trusttunnel-web-local.patch). Исходная лицензия MIT сохраняется при клонировании. Пример тега сборки: `trusttunnel-web:local-fd8c6ef-v1.1.0`.

Проверка скачанного файла: `sha256sum <файл>` и сравнение с таблицей/официальными метаданными. Не используйте хеш одного архитектурного артефакта для другого. Контрольная сумма обеспечивает соответствие выбранному файлу, не заменяет аудит.

Docker base `python:3.12-slim` и транзитивные Python-зависимости не закреплены digest/полным lockfile: новая сборка не обязана быть побитово идентична. Для обновления сначала сохраните рабочий image ID и данные, затем проверьте новую сборку отдельно.

## Технические первоисточники

- [Hysteria: ACL](https://v2.hysteria.network/docs/advanced/ACL/)
- [Hysteria: полный server config](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Hysteria: TLS клиента](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [H UI](https://github.com/jonssonyan/h-ui)
- [sing-box configuration](https://sing-box.sagernet.org/configuration/)
- [TrustTunnel CONFIGURATION](https://github.com/TrustTunnel/TrustTunnel/blob/master/CONFIGURATION.md)
- [TrustTunnel Client](https://github.com/TrustTunnel/TrustTunnelClient)
- [GeoIP Loyalsoldier](https://github.com/Loyalsoldier/v2ray-rules-dat/releases)

GeoIP берётся из release assets `geoip.dat` и `geoip.dat.sha256sum`; версия базы меняется независимо от ядра.
