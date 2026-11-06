# Как предлагать изменения в NPMOS

Правила общения, оформление багов и фич и архитектура — в [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Подробные
правила кода и команды — в [CLAUDE.md](CLAUDE.md).

## Порядок работы

1. Для заметного изменения сначала issue (фича или баг по шаблону): обсудим подход до кода.
2. Ветка от `main`, один pull request — одна задача. Описание: что изменилось, зачем, как проверено.
3. CI должен быть зелёным: линт, типы, юнит-тесты, сборка образов и тест закрытого контура (`scripts/test-airgap.sh`).
4. Новая возможность — вместе со сценарием в `deploy/test/smoke.sh` и пунктом в `docs/CHECKLIST.md`.

## Обязательные правила

- **Всё из GUI.** Возможность включается и настраивается в интерфейсе. Если нужен compose, `cscli` или ручная
  правка файлов — задача не закончена (что пока осталось в env — `docs/ENV-INVENTORY.md`).
- **Local-first.** Без интернета всё работает; обращение наружу — только опция администратора, с таймаутом;
  недоступный внешний сервис не блокирует запуск.
- **Код NPMOS** — в `npmos/backend/npmos/` и `npmos/frontend/src/npmos/`. В файлах upstream (NPMplus) — точечные
  изменения с комментарием `NPMOS: <причина>`: по этим меткам разрешаются конфликты при обновлении NPMplus.
- **Строки интерфейса** — только в `npmos/frontend/src/locale/src/en.json` и `ru.json`, текст прямо в разметке
  запрещён (`scripts/check-i18n.mjs`).
- **Стиль** — biome (табы, ширина 120), ESM, `async/await`. Перед коммитом `pnpm biome format --write`.
- **Секреты** не попадают в compose, env-файлы, логи и ответы API.

## Проверки перед pull request

```bash
cd npmos/backend && pnpm install --frozen-lockfile && pnpm biome ci . --assist-enabled=false \
  && node --test 'npmos/**/*.test.js'
cd npmos/frontend && pnpm install --frozen-lockfile && pnpm biome ci . --assist-enabled=false \
  && node check-locales.cjs && node ../../scripts/check-i18n.mjs && pnpm tsc --noEmit && pnpm vitest run
shellcheck -S warning scripts/*.sh deploy/*/*.sh
docker compose -f deploy/compose.yaml config -q
```

## Коммиты

Conventional Commits на английском: `fix(acme): …`, `feat(waf): …`, `refactor(deploy): …`, `docs: …`,
`test(smoke): …`. В теле — что было не так, что изменилось и как проверено.
