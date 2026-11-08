# NginxionS

**NginxionS** — reverse proxy с единой панелью управления безопасностью: форк [NPMplus](https://github.com/ZoeyVid/NPMplus) (основа) + функциональность [open-appsec-npm](https://github.com/openappsec/open-appsec-npm) + ML-WAF [open-appsec](https://github.com/openappsec/openappsec) + [CrowdSec](https://www.crowdsec.net).

## Главные принципы

1. **Всё управляется через GUI NginxionS.** После `docker compose up -d` не нужны ни терминал, ни ручная правка файлов, ни `cscli`/`open-appsec-ctl`, ни облачные консоли. Прокси, open-appsec, CrowdSec, сертификаты и mTLS, пользователи и роли, системные настройки — всё в одной панели.
2. **Никакой зависимости от облака.** open-appsec и CrowdSec работают полностью локально и автономно, их облачные консоли (my.openappsec.io, app.crowdsec.net) заменяет NginxionS. Интернет — только опция, которую администратор включает сам (например, Let's Encrypt).

## Возможности

- Управление open-appsec из GUI: WAF по хостам и локациям, визуальный редактор политики, события, аналитика, обучение агента и разметка ложных срабатываний.
- Управление CrowdSec из GUI: решения, алерты, hub, источники логов, профили реагирования, белые списки, AppSec.
- Сертификаты ACME от любого центра сертификации: Let's Encrypt, ZeroSSL, Google Trust Services, SSL.com, ТЦИ / НУЦ Минцифры или свой ACME-сервер; проверка по HTTP или DNS, свой CSR; клиенты certbot и lego.
- Собственный PKI и mTLS: защита хоста одним переключателем, выдача, скачивание, отзыв и удаление сертификатов доступа прямо в интерфейсе («Сертификаты → mTLS»).
- RBAC с ролями, настраиваемыми в GUI, и OIDC-группами.
- Интерфейс на русском и английском, редизайн на токенах opensophy UI.

## Запуск

```bash
git clone https://github.com/opensophy-projects/NPMOS nginxions && cd nginxions
docker compose -f deploy/compose.yaml up -d
```

Откройте `https://<адрес-сервера>:81` и создайте первого администратора. Пароли сервисов генерируются автоматически, `.env` не нужен. Стек работает без доступа в интернет.

Требования: Docker Engine 26+ и Compose 2.23+.

По умолчанию NginxionS слушает только IPv4: так он запускается на любом хосте, в том числе с выключенным или неработающим IPv6. Чтобы nginx слушал и IPv6 (и видел настоящие IPv6-адреса клиентов), добавьте в `deploy/.env` строку `NGINXIONS_DISABLE_IPV6=false` и перезапустите стек; IPv6 на хосте должен работать.

Если `docker compose pull` падает с `TLS handshake timeout` (у некоторых провайдеров, в том числе в России, соединение Docker с Docker Hub обрывается, хотя `curl` до него доходит), пропишите зеркало Docker Hub — см. [TESTING-DEVELOP.md](docs/TESTING-DEVELOP.md#2-что-нужно-на-машине).

Переезд с Nginx Proxy Manager, NPMplus или open-appsec-npm — в «Администрирование → Настройки → Перенос»: хосты, сертификаты, списки доступа, пользователи и WAF-правила переносятся из архива старой установки ([подробнее](docs/MIGRATION.md)).

Стек — четыре контейнера: `nginxions` (nginx, панель, backend), `openappsec` (WAF-агент, его сервисы обучения и управление Docker для «Обзор → Сервисы»), `crowdsec` и `postgres`; при старте один раз отрабатывает `nginxions-init`. Схема и устройство — в [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md#3-архитектура-nginxions).

Образы публикуются в Docker Hub (`opensophy/nginxions`, `opensophy/nginxions-openappsec`) после слияния в ветку `work` (тег `develop`) и при выпуске версии (`X.Y.Z`, `latest`). Версии всех образов закреплены в `deploy/.env`.

Собрать образы самому (первая сборка `nginxions` и агента open-appsec занимает 30–60 минут):

```bash
scripts/build-images.sh
NGINXIONS_REGISTRY=local NGINXIONS_VERSION=dev docker compose -f deploy/compose.yaml up -d
```

## Разработка и просмотр изменений интерфейса

```bash
# backend и весь стек из локальных исходников (собирается за секунды)
docker compose -f deploy/compose.yaml -f deploy/compose.dev.yaml up -d --build

# интерфейс с горячей перезагрузкой: правки CSS/компонентов видны сразу
cd nginxions/frontend
pnpm install
pnpm vite
```

Интерфейс откроется на `http://localhost:5173`. Он ходит в backend на `https://127.0.0.1:81` (адрес можно поменять через `NGINXIONS_API`).

Нужны Docker, Node.js 22+ и pnpm (`npm i -g pnpm`).

Подробнее о командах и правилах — в [CLAUDE.md](CLAUDE.md) и [CONTRIBUTING.md](CONTRIBUTING.md). Как оформлять баги, предложения и вопросы — в [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Документация

- [Перенос с Nginx Proxy Manager, NPMplus и open-appsec-npm](docs/MIGRATION.md)
- [Полное удаление NginxionS](docs/UNINSTALL.md)
- [Решение проблем: браузер перенаправляет на старый адрес](docs/TROUBLESHOOTING.md)
- [Как развернуть develop-версию и что проверить руками](docs/TESTING-DEVELOP.md)
- [План разработки](docs/ROADMAP.md)
- [Инвентаризация env-настроек](docs/ENV-INVENTORY.md)
- [ADR-0001: сеть стека](docs/adr/0001-network.md)

## Структура репозитория

| Папка | Что это |
|---|---|
| `nginxions/` | Основа NginxionS: NPMplus (git subtree) и наши изменения |
| `deploy/` | Compose-файлы стека, образ `nginxions-openappsec`, bootstrap (`init/`), тест закрытого контура |
| `scripts/` | Сборка образов, тест закрытого контура, проверка переводов |
| `docs/` | План и документация |
