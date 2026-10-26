# NPMOS — правила разработки

NPMOS — форк NPMplus с встроенными open-appsec (ML-WAF) и CrowdSec. План: `docs/ROADMAP.md`.

## Два главных правила

1. **Всё управляется через GUI NPMOS.** Любая новая возможность включается и настраивается в интерфейсе. Если для неё нужно править compose, запускать `cscli`/`open-appsec-ctl` или редактировать файлы руками — задача не закончена. Что пока осталось в env, перечислено в `docs/ENV-INVENTORY.md`, и там же указано, когда это уходит в GUI.
2. **Local-first: никакой зависимости от облака.** Без интернета всё работает. Обращение наружу (ACME, обновления, hub CrowdSec, Gravatar…) — только опция, которую включает администратор, и она всегда с таймаутом. Недоступный внешний сервис не должен блокировать запуск. Проверяется тестом `scripts/test-airgap.sh`; каждая фаза добавляет сценарии в `deploy/test/smoke.sh`.

## Структура

| Путь | Что | Правила |
|---|---|---|
| `app/` | NPMplus (git subtree, upstream `ZoeyVid/NPMplus`) + наши изменения | см. «Изменения в upstream-коде» |
| `app/backend/npmos/`, `app/frontend/src/npmos/` | Наш код (модули NPMOS) | Новый код — сюда |
| `deploy/` | `compose.yaml` (прод, локальный стек), `compose.dev.yaml`, образ `crowdsec/`, `init/`, `test/` | |
| `reference/` | Исходники open-appsec-npm, open-appsec, smartsync(-tuning) — только для чтения | Не собирается, не линтится, не правится. Обновление: `scripts/update-reference.sh` |
| `design/` | Токены дизайна, пример sidebar | |
| `docs/` | План, ADR, инвентаризация env | |

## Изменения в upstream-коде (`app/`)

- Предпочитать новый код в `npmos/`-каталогах и точечные «крючки» в upstream-файлах.
- Каждое изменение upstream-файла помечается комментарием `NPMOS:` с причиной (`// NPMOS: …`, `# NPMOS: …`). По этим меткам разрешаются конфликты при обновлении.
- Стиль — как в окружающем коде: биом-форматирование (табы, ширина 120), ESM, `async/await`.
- Новые строки интерфейса — только в `en.json` и `ru.json` (`app/frontend/src/locale/src/`).

## Обновление NPMplus

```bash
git subtree pull --prefix=app https://github.com/ZoeyVid/NPMplus <tag> --squash
```

После этого: разрешить конфликты по меткам `NPMOS:`, поменять `NPMPLUS_BASE` в `deploy/dev/Dockerfile` на тот же тег, прогнать проверки и закрытый контур. Текущий тег: **2026-10-14-r1**.

## Команды проверки

```bash
# backend
cd app/backend && pnpm install --frozen-lockfile && pnpm biome ci . --assist-enabled=false
# frontend
cd app/frontend && pnpm install --frozen-lockfile && pnpm biome ci . --assist-enabled=false \
  && node check-locales.cjs && pnpm formatjs compile-folder src/locale/src src/locale/lang \
  && pnpm tsc --noEmit && pnpm vitest run
# shell, compose
shellcheck -S warning scripts/*.sh deploy/*/*.sh
docker compose -f deploy/compose.yaml config -q
# закрытый контур (нужны образы npmos и npmos-crowdsec, см. ниже)
scripts/test-airgap.sh
```

`--assist-enabled=false`: upstream не соблюдает порядок импортов biome, массово его не исправляем (конфликты при обновлении).

## Разработка

```bash
docker compose -f deploy/compose.yaml -f deploy/compose.dev.yaml up -d --build   # backend + стек
docker compose -f deploy/compose.yaml -f deploy/compose.dev.yaml watch           # синхронизация backend
cd app/frontend && pnpm install && pnpm vite                                     # http://localhost:5173
```

- Dev-образ `npmos:dev` = upstream-образ того же тега + наши `app/backend` и `app/rootfs`. Собирается за секунды. Прод-образ собирается из `app/Dockerfile` в CI.
- Vite проксирует `/api` на `NPMOS_API` (по умолчанию `https://127.0.0.1:81`) и подменяет Origin.
- Без IPv6 на хосте: `NPMOS_DISABLE_IPV6=true`.
- Генератор атак для проверки WAF: `--profile attack`.

## Безопасность

- Секреты генерирует `npmos-init` в томе `secrets`. Каждый сервис монтирует только свой подкаталог (`subpath`). Пароли не попадают в compose и env-файлы.
- Сервисы, кроме `npmos`, сидят во внутренних сетях без выхода наружу.
- Доступ к Docker — только через `socket-proxy` и (с фазы 1) `npmos-control` с белым списком операций и аудитом.
