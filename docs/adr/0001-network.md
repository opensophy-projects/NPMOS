# ADR-0001. Сеть стека: bridge с публикацией портов вместо `network_mode: host`

**Статус:** принято (фаза 0). **Дата:** 2026-10-26.

## Контекст

NPMplus рекомендует `network_mode: host`. NPMOS — это стек из нескольких сервисов: агент open-appsec, smartsync, shared-storage, tuning, Postgres, CrowdSec, socket-proxy. Им нужно:

- находить друг друга по именам (`SHARED_STORAGE_HOST=appsec-shared-storage` и т. п.);
- быть изолированными от интернета (local-first) и от хоста;
- агенту — работать в одном network- и IPC-namespace с nginx (attachment).

В host-режиме DNS Docker недоступен, внутренние сервисы пришлось бы публиковать на портах хоста, а изоляцию — делать файрволом хоста.

## Решение

- Сеть `edge` (bridge) — только у `npmos`. Наружу опубликованы порты 80/tcp, 443/tcp+udp и 81/tcp (`NPMOS_*_PORT`).
- Сеть `internal` (`internal: true`, без выхода в интернет): `npmos`, Postgres, сервисы обучения, CrowdSec.
- Сеть `control` (`internal: true`): socket-proxy и, с фазы 1, `npmos-control`.
- Агент: `network_mode: service:npmos` и `ipc: service:npmos` — тот же стек сети и IPC, что у nginx, без `ipc: host`.

## Последствия

- **IP клиента сохраняется.** Для IPv4 Docker пробрасывает опубликованные порты через DNAT (iptables/nftables), поэтому nginx видит настоящий адрес. Внутри сети это проверяет закрытый контур (`X-Real-IP` у upstream).
- **Исключения**, где IP подменяется: при `userland-proxy` (запросы на опубликованный порт с самого хоста, `localhost`) и для IPv6 без `ip6tables` в Docker (по умолчанию включён с Docker 27). Для IPv6 в проде требуется `"ip6tables": true` (это значение по умолчанию) в `daemon.json`.
- **Недоступно в bridge:** MPTCP (`ENABLE_MPTCP`) и `NGINX_QUIC_BPF` — им нужен host-режим. Если они понадобятся, это будет отдельный профиль compose «host» с публикацией внутренних сервисов только на `127.0.0.1` (фаза 4, по запросу).
- **Выход в интернет** есть только у `npmos` через `edge`, и он нужен лишь для того, что включил администратор (ACME, загрузка обновлений). Внутренние сервисы физически не могут обратиться наружу.
