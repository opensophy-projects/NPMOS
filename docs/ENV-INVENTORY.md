# Инвентаризация env-настроек

Принцип «всё через GUI» означает, что после `docker compose up -d` администратор ничего не правит в compose-файле. Каждую переменную окружения NPMplus, агента open-appsec и CrowdSec относим к одному из классов:

- **Bootstrap.** Нужна до запуска backend: порты, сеть, БД, секреты. Остаётся в env, имеет безопасное значение по умолчанию в `deploy/compose.yaml`, в GUI показывается только для чтения (страница «Система → Сервисы», фаза 1).
- **GUI (фаза N).** Переносится в настройки NPMOS, которые хранятся в БД. Env остаётся только как значение для первого запуска; если значение в БД задано, оно приоритетнее env.
- **NPMOS фиксирует.** Значение задаёт NPMOS, администратору его менять не нужно (часто ради local-first).

Изменение настройки из GUI, которая сейчас читается в `envs.sh`/`start.sh` при старте, требует перезапуска процесса. Перезапуск делает сам NPMOS через `npmos-control` (фаза 1), а не администратор.

## NPMplus (контейнер `npmos`)

| Переменная | Upstream по умолчанию | NPMOS по умолчанию | Класс | Фаза |
|---|---|---|---|---|
| `TZ` | — (обязательна) | `UTC` | GUI (Система → Настройки) | 4 |
| `PUID`, `PGID` | `0` | `0` | Bootstrap | — |
| `HTTP_PORT`, `HTTPS_PORT`, `NPM_PORT`, `GOA_PORT` | 80, 443, 81, 91 | те же; внешние порты — `NPMOS_*_PORT` | Bootstrap | — |
| `IPV4_BINDING`, `IPV6_BINDING`, `NPM_*_BINDING`, `GOA_*_BINDING`, `*_LISTEN_LOCALHOST` | все адреса | те же | Bootstrap | — |
| `DISABLE_IPV6` | `false` | `NPMOS_DISABLE_IPV6`, `false` | Bootstrap | — |
| `DISABLE_HTTP`, `DISABLE_H3_QUIC`, `ENABLE_MPTCP`, `NGINX_QUIC_BPF` | `false` | `false` | GUI (Система → Сеть) | 4 |
| `LISTEN_PROXY_PROTOCOL*` | `false` | `false` | GUI (Система → Сеть) | 4 |
| `DB_POSTGRES_*` | — (SQLite) | Postgres из compose, пароль из `DB_POSTGRES_PASSWORD_FILE` | Bootstrap | 0 ✅ |
| `DB_MYSQL_*` | — | не используется | Bootstrap (поддержка upstream сохраняется) | — |
| `COOKIE_SECRET` | случайный при каждом старте | `COOKIE_SECRET_FILE` от `npmos-init` ✅ | Bootstrap (секрет) | 0 |
| `INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_PASSWORD` | — | не задаём: первый админ создаётся мастером в GUI | Bootstrap | — |
| `ACME_SERVER`, `ACME_EMAIL`, `ACME_EAB_KID`, `ACME_EAB_HMAC_KEY`, `ACME_PROFILE`, `ACME_KEY_TYPE`, `ACME_KEY_SIZE`, `ACME_MUST_STAPLE`, `ACME_OCSP_STAPLING`, `ACME_SERVER_TLS_VERIFY` | Let's Encrypt | Let's Encrypt; аккаунт регистрируется при первом запросе сертификата, при старте обращений нет ✅ | GUI (Сертификаты → ACME) | 6 |
| `CUSTOM_OCSP_STAPLING` | `false` | `false` | GUI (Сертификаты) | 6 |
| `CERTBOT_RUN_INTERVAL` | 3 ч | 3 ч | GUI (Сертификаты) | 6 |
| `DEFAULT_CERT_ID` | 0 | 0 | GUI (Система → Настройки) | 4 |
| `ECH_ROTATION_INTERVAL` | 1 ч | 1 ч | GUI (Сертификаты) | 6 |
| `NGINX_WORKER_PROCESSES`, `NGINX_WORKER_CONNECTIONS`, `NGINX_LOG_NOT_FOUND` | auto, 512, false | те же | GUI (Система → Nginx) | 4 |
| `NGINX_FORCE_X25519MLKEM768`, `NGINX_DISABLE_TLS12`, `NGINX_TRUST_SECPR1`, `NGINX_TRUST_RSA_PKCS1` | | те же | GUI (Система → TLS) | 4 |
| `DISABLE_NGINX_BEAUTIFIER` | `false` | `false` | NPMOS фиксирует | — |
| `NGINX_LOAD_OPENAPPSEC_ATTACHMENT_MODULE` | `false` | `false` | GUI (WAF → Агент: «Включить WAF») | 1 |
| `NGINX_LOAD_NJS_MODULE`, `NGINX_LOAD_GEOIP2_MODULE`, `NGINX_LOAD_LDAP_MODULE`, `NGINX_LOAD_NTLM_MODULE`, `NGINX_LOAD_VHOST_TRAFFIC_STATUS_MODULE` | `false` | `false` | GUI (Система → Модули nginx) | 4 |
| `TRUST_CLOUDFLARE` | `false` | `false` (загрузка IP-диапазонов Cloudflare — только при явном включении) | GUI (Система → Сеть) | 4 |
| `DISABLE_GRAVATAR` | `false` | **`true`** ✅ | GUI (Система → Внешние сервисы) | 4 |
| `NPMOS_CHECK_VERSION` | — (проверка всегда включена) | **`false`** ✅ | GUI (Система → Обновления) | 4 |
| `LOGROTATE`, `LOGROTATIONS` | `false`, 3 | **`true`** (логи нужны CrowdSec и аналитике), 3 | NPMOS фиксирует `LOGROTATE`; срок хранения — GUI | 4 |
| `GOA`, `GOACLA` | `false` | `false` | Заменяется аналитикой NPMOS | 4 |
| `PHP83`, `PHP84`, `PHP85` | `false` | `false` | GUI (Система → PHP) | 4 |
| `INITIAL_DEFAULT_PAGE` | `congratulations` | то же | NPMOS фиксирует (настройка «страница по умолчанию» уже есть в GUI upstream) | — |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_DOMAIN`, `OIDC_REQUIRE_VERIFIED_EMAIL`, `OIDC_DISABLE_PASSWORD` | — | — | GUI (Администрирование → Вход через OIDC) | 3 |
| `AUTH_REQUEST_*_UPSTREAM` (Anubis, Tinyauth, oauth2-proxy, VoidAuth, Authelia, Authentik) | — | — | GUI (Безопасность → Внешняя аутентификация) | 4 |
| `ENABLE_PRERUN` | `false` | `false` | NPMOS фиксирует (скрипты до запуска противоречат «всё через GUI») | — |
| `NODE_TLS_REJECT_UNAUTHORIZED` | — | — | Не используется; доверенные CA для OIDC/ACME добавляются в GUI | 6 |
| `REGENERATE_ALL` | — | — | Кнопка «Пересоздать конфигурацию» в Система → Сервисы | 1 |
| `NC_AIO`, `NC_DOMAIN` | — | — | Интеграция Nextcloud AIO upstream; не трогаем | — |

## Агент open-appsec (`appsec-agent`)

| Переменная | NPMOS | Класс | Фаза |
|---|---|---|---|
| `AGENT_TOKEN` | **не задаётся** (hybrid-режим без облака) | NPMOS фиксирует | 0 ✅ |
| `user_email` | не задаётся | NPMOS фиксирует | 0 ✅ |
| `autoPolicyLoad` | `true` (агент сам применяет `local_policy.yaml`, который генерирует NPMOS) | NPMOS фиксирует | 0 ✅ |
| `nginxproxymanager` | `true` | NPMOS фиксирует; проверить, нужен ли с NPMplus | 1 |
| `SHARED_STORAGE_HOST`, `LEARNING_HOST`, `TUNING_HOST` | имена сервисов compose | Bootstrap | 0 ✅ |
| `https_proxy` | не задаётся | GUI (Система → Внешние сервисы), только если администратор включит онлайн-функции | 4 |
| `CROWDSEC_ENABLED`, `CROWDSEC_API_URL`, `CROWDSEC_API_KEY` (встроенная интеграция агента) | выключено | GUI (WAF → Агент) | 7 |
| Advanced ML-модель | файл `/advanced-model/open-appsec-advanced-model.tgz` | Загрузка файла в GUI (WAF → Агент) | 1 |

Режим (prevent/detect), `minimum-confidence`, практики, триггеры и исключения — это не env, а `local_policy.yaml`. Его целиком генерирует NPMOS из своей БД (фазы 1 и 5).

## Сервисы обучения open-appsec

| Сервис | Переменная | NPMOS | Класс |
|---|---|---|---|
| `appsec-tuning-svc` | `QUERY_DB_HOST`, `QUERY_DB_USER` | `postgres`, роль `appsec` (CREATEDB) | Bootstrap |
| `appsec-tuning-svc` | `QUERY_DB_PASSWORD` | `QUERY_DB_PASSWORD_FILE` (entrypoint образа NPMOS), секрет от `npmos-init` | Bootstrap (секрет) ✅ |
| `appsec-smartsync`, `appsec-tuning-svc` | `SHARED_STORAGE_HOST` | `appsec-shared-storage` | Bootstrap |

## CrowdSec (`crowdsec`, официальный образ `crowdsecurity/crowdsec`)

Тома конфигурации и данных при первом старте наполняет `npmos-init` из офлайн-снимка hub, встроенного в образ NPMOS.


| Переменная | NPMOS | Класс | Фаза |
|---|---|---|---|
| `DISABLE_ONLINE_API` | **`true`** (без CAPI: никаких сигналов наружу и community blocklist) | GUI (CrowdSec → Онлайн-функции, по умолчанию выключено) | 7 |
| `NO_HUB_UPGRADE` | `true` | NPMOS фиксирует; hub обновляется из GUI (загрузка снимка или онлайн по кнопке) | 7 |
| `cscli.__hub_url_template__` (config.yaml) | `http://npmos/.npmos/crowdsec-hub/%s/%s` — источник hub это NPMOS, не CDN | NPMOS фиксирует; раздача снимков — фаза 7 | 0 ✅ |
| `cscli.hub_branch` (config.yaml) | `master` (не спрашивать version.crowdsec.net) | NPMOS фиксирует | 0 ✅ |
| Ключ bouncer `npmos` | файл `/run/secrets/bouncer_key_npmos` от `npmos-init` (штатный механизм образа) | Bootstrap (секрет) ✅ | 0 |
| `COLLECTIONS`, `PARSERS`, `SCENARIOS`, `POSTOVERFLOWS` (+`DISABLE_*`) | не задаются; базовый набор во встроенном снимке hub | GUI (CrowdSec → Hub) | 7 |
| `ENROLL_KEY`, `ENROLL_INSTANCE_NAME`, `ENROLL_TAGS` | не задаются (без app.crowdsec.net) | NPMOS фиксирует | 0 ✅ |
| `USE_WAL` | `true` | NPMOS фиксирует | — |
| `TZ` | общий с NPMOS | GUI | 4 |
| Источники логов (`acquis.d`), профили, белые списки, AppSec | файлы в томе `crowdsec-conf` | GUI (CrowdSec) | 7 |

## Compose-уровень (нельзя изменить из GUI)

Задаются один раз в `deploy/compose.yaml` и меняются только при обновлении NPMOS:

- сети `edge`, `internal`, `control` (у последних двух нет выхода в интернет);
- `ipc: shareable` у `npmos` и `ipc: service:npmos` у агента, tmpfs-том `appsec-shm`;
- общие тома: `appsec-localconfig` (политика), `appsec-logs` (события, только чтение для NPMOS и CrowdSec), логи nginx для CrowdSec;
- метки `npmos.managed=true`, по которым `npmos-control` решает, чем можно управлять;
- `socket-proxy`: только `CONTAINERS` и `ALLOW_RESTARTS`;
- образы и версии (`deploy/.env`): `NPMOS_REGISTRY`, `NPMOS_VERSION`, `CROWDSEC_VERSION`, `POSTGRES_VERSION`, `SOCKET_PROXY_VERSION`.

## Обращения наружу только по действию администратора

При обычной работе NPMOS не выходит в интернет (это проверяет тест закрытого контура). Следующие обращения происходят только после явного действия в GUI. В GUI они должны быть помечены как «требует интернет»:

| Действие | Куда | Фаза, в которой довести до local-first |
|---|---|---|
| Запрос и продление ACME-сертификата (первый запрос регистрирует аккаунт) | `ACME_SERVER`, для ZeroSSL — api.zerossl.com | 6: свой ACME-сервер/PKI как локальная альтернатива |
| DNS-challenge: установка DNS-плагина certbot (`pip install` при первом использовании провайдера) | PyPI | 6: предустановленные плагины для популярных провайдеров или загрузка wheel через GUI |
| «Проверить доступность» домена при выпуске сертификата | site24x7.com | 6: проверка без внешнего сервиса или явное предупреждение |
| OCSP stapling (`ACME_OCSP_STAPLING`, `CUSTOM_OCSP_STAPLING`) | OCSP-респондеры CA | 6 |
| Вход через OIDC | указанный IdP (рекомендуется локальный) | 3 |
| Проверка обновлений, Gravatar, IP-диапазоны Cloudflare | api.github.com, gravatar.com, cloudflare.com | выключены по умолчанию ✅ |
