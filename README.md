# NPMOS

**NPMOS** — reverse proxy с единой панелью управления безопасностью: форк [NPMplus](https://github.com/ZoeyVid/NPMplus) (основа) + функциональность [open-appsec-npm](https://github.com/openappsec/open-appsec-npm) + ML-WAF [open-appsec](https://github.com/openappsec/openappsec) + [CrowdSec](https://www.crowdsec.net).

## Главные принципы

1. **Всё управляется через GUI NPMOS.** После `docker compose up -d` не нужны ни терминал, ни ручная правка файлов, ни `cscli`/`open-appsec-ctl`, ни облачные консоли. Прокси, open-appsec, CrowdSec, сертификаты и mTLS, пользователи и роли, системные настройки — всё в одной панели.
2. **Никакой зависимости от облака.** open-appsec и CrowdSec работают полностью локально и автономно, их облачные консоли (my.openappsec.io, app.crowdsec.net) заменяет NPMOS. Интернет — только опция, которую администратор включает сам (например, Let's Encrypt).

## Возможности (план)

- Управление open-appsec из GUI: WAF по хостам и локациям, визуальный редактор политики, события, аналитика, обучение агента и разметка ложных срабатываний.
- Управление CrowdSec из GUI: решения, алерты, hub, источники логов, профили реагирования, белые списки, AppSec.
- Собственный PKI и mTLS: выпуск, отзыв, сроки и выдача клиентских сертификатов.
- RBAC с ролями, настраиваемыми в GUI, и OIDC-группами.
- Интерфейс на русском и английском, редизайн на токенах opensophy UI.

## Запуск

```bash
git clone https://github.com/opensophy-projects/npmos && cd npmos
docker compose -f deploy/compose.yaml up -d
```

Откройте `https://<адрес-сервера>:81` и создайте первого администратора. Пароли сервисов генерируются автоматически, `.env` не нужен. Стек работает без доступа в интернет.

Требования: Docker Engine 26+ и Compose 2.23+.

Переезд с Nginx Proxy Manager, NPMplus или open-appsec-npm — в «Система → Настройки → Перенос»: хосты, сертификаты, списки доступа, пользователи и WAF-правила переносятся из архива старой установки ([подробнее](docs/MIGRATION.md)).

Образы публикуются в Docker Hub `opensophy/npmos*` после слияния в ветку `work` (тег `develop`) и при выпуске версии (`X.Y.Z`, `latest`). Версии всех образов закреплены в `deploy/.env`.

Собрать образы самому (первая сборка `npmos` и агента open-appsec занимает 30–60 минут):

```bash
scripts/build-images.sh
NPMOS_REGISTRY=local NPMOS_VERSION=dev docker compose -f deploy/compose.yaml up -d
```

## Разработка и просмотр изменений интерфейса

```bash
# backend и весь стек из локальных исходников (собирается за секунды)
docker compose -f deploy/compose.yaml -f deploy/compose.dev.yaml up -d --build

# интерфейс с горячей перезагрузкой: правки CSS/компонентов видны сразу
cd npmos/frontend
pnpm install
pnpm vite
```

Интерфейс откроется на `http://localhost:5173`. Он ходит в backend на `https://127.0.0.1:81` (адрес можно поменять через `NPMOS_API`).

Нужны Docker, Node.js 22+ и pnpm (`npm i -g pnpm`). На хосте без IPv6 добавьте `NPMOS_DISABLE_IPV6=true` перед `docker compose`.

Подробнее о командах и правилах — в [CLAUDE.md](CLAUDE.md).

## Документация

- [Перенос с Nginx Proxy Manager, NPMplus и open-appsec-npm](docs/MIGRATION.md)
- [Полное удаление NPMOS](docs/UNINSTALL.md)
- [Как развернуть develop-версию и что проверить руками](docs/TESTING-DEVELOP.md)
- [План разработки](docs/ROADMAP.md)
- [Инвентаризация env-настроек](docs/ENV-INVENTORY.md)
- [ADR-0001: сеть стека](docs/adr/0001-network.md)

## Структура репозитория

| Папка | Что это |
|---|---|
| `npmos/` | Основа NPMOS: NPMplus (git subtree) и наши изменения |
| `deploy/` | Compose-файлы стека, образы open-appsec, bootstrap (`init/`), тест закрытого контура |
| `reference/` | Исходники open-appsec-npm, open-appsec, smartsync, smartsync-tuning — справочно ([версии](reference/VERSIONS.md)) |
| `design/` | Токены дизайна и пример sidebar |
| `scripts/` | Сборка образов, тест закрытого контура, обновление `reference/` |
| `docs/` | План и документация |
