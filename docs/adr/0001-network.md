# ADR-0001. Сеть стека: bridge с публикацией портов вместо `network_mode: host`

**Статус:** принято (фаза 0). **Дата:** 2026-10-26.

## Контекст

NPMplus рекомендует `network_mode: host`. NginxionS — это стек из нескольких сервисов: агент open-appsec, smartsync, shared-storage, tuning, Postgres, CrowdSec, socket-proxy. Им нужно:

- находить друг друга по именам (`SHARED_STORAGE_HOST=appsec-shared-storage` и т. п.);
- быть изолированными от интернета (local-first) и от хоста;
- агенту — работать в одном network- и IPC-namespace с nginx (attachment).

В host-режиме DNS Docker недоступен, внутренние сервисы пришлось бы публиковать на портах хоста, а изоляцию — делать файрволом хоста.

## Решение

- Сеть `edge` (bridge) — только у `nginxions`. Наружу опубликованы порты 80/tcp, 443/tcp+udp и 81/tcp (`NGINXIONS_*_PORT`).
- Сеть `internal` (`internal: true`, без выхода в интернет): `nginxions`, Postgres, сервисы обучения, CrowdSec.
- Сеть `control` (`internal: true`): socket-proxy и, с фазы 1, `nginxions-control`.
- Агент: `network_mode: service:nginxions` и `ipc: service:nginxions` — тот же стек сети и IPC, что у nginx, без `ipc: host`.

## Последствия

- **IP клиента сохраняется.** Для IPv4 Docker пробрасывает опубликованные порты через DNAT (iptables/nftables), поэтому nginx видит настоящий адрес. Внутри сети это проверяет закрытый контур (`X-Real-IP` у upstream).
- **Исключения**, где IP подменяется: при `userland-proxy` (запросы на опубликованный порт с самого хоста, `localhost`) и для IPv6 без `ip6tables` в Docker (по умолчанию включён с Docker 27). Для IPv6 в проде требуется `"ip6tables": true` (это значение по умолчанию) в `daemon.json`.
- **Недоступно в bridge:** MPTCP (`ENABLE_MPTCP`) и `NGINX_QUIC_BPF` — им нужен host-режим. Если они понадобятся, это будет отдельный профиль compose «host» с публикацией внутренних сервисов только на `127.0.0.1` (фаза 4, по запросу).
- **Выход в интернет** есть только у `nginxions` через `edge`, и он нужен лишь для того, что включил администратор (ACME, загрузка обновлений). Внутренние сервисы физически не могут обратиться наружу.

## Пересмотр (ноябрь 2026): четыре контейнера

Стек сокращён до `nginxions`, `openappsec`, `crowdsec`, `postgres` (+ разовый `nginxions-init`):

- Агент open-appsec, его shared storage и tuning и `nginxions-control` работают в одном контейнере `openappsec`
  (образ `nginxions-openappsec`). Он владеет сетью и IPC: опубликованные порты — на нём, `nginxions` подключается к нему
  (`network_mode`/`ipc: service:openappsec`), в сетях у него псевдоним `nginxions`. Сервисы слушают на 127.0.0.1:
  агент 7777, `nginxions-control` 7080, shared storage 7811, tuning 7813 (порт 80 занят nginx; агент получил адреса с
  портом изменением NginxionS в своём коде).
- `socket-proxy` и сеть `control` убраны: `nginxions-control` обращается к `/var/run/docker.sock` сам и ограничивает
  операции своим белым списком (список, логи, перезапуск, reload контейнеров стека с меткой `nginxions.managed`),
  слушает только 127.0.0.1, требует токен. Сокет смонтирован только в `openappsec`; `nginxions`, принимающий трафик
  из интернета, Docker не видит. Второго слоя фильтрации (haproxy) больше нет — это осознанный обмен на меньшее
  число контейнеров.
- «Перезапуск» `openappsec` из GUI перезапускает процесс агента (не контейнер, в котором работает сам
  `nginxions-control`), затем `nginxions`, чтобы attachment nginx подключился к новому агенту. Перезапуск `nginxions` агент не
  трогает. Watchdog `nginxions-control` перезапускает `nginxions`, если `openappsec` перезапустили в обход NginxionS.
