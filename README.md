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

## Документация

- [План разработки](docs/ROADMAP.md)

## Структура репозитория (текущая)

| Папка | Что это |
|---|---|
| `NPMplus/` | Основа NPMOS (форк NPMplus) |
| `open-appsec-npm-master/` | Интеграция open-appsec с NPM — источник логики для переноса |
| `openappsec-main/` | Исходники агента open-appsec (справочно) |
| `smartsync-main/`, `smartsync-tuning-main/` | Локальные сервисы обучения и тюнинга open-appsec (справочно) |
| `docs/` | План и документация |

Целевая структура монорепо описана в [плане](docs/ROADMAP.md#3-целевая-архитектура).
