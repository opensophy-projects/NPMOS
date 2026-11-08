# Инвентаризация env-настроек

Принцип «всё через GUI» означает, что после `docker compose up -d` администратор ничего не правит в compose-файле. Каждую переменную окружения NPMplus, агента open-appsec и CrowdSec относим к одному из классов:

- **Bootstrap.** Нужна до запуска backend: порты, сеть, БД, секреты. Остаётся в env, имеет безопасное значение по умолчанию в `deploy/compose.yaml`, в GUI показывается только для чтения (страница «Обзор → Сервисы», фаза 1).
- **GUI (фаза N).** Переносится в настройки NginxionS, которые хранятся в БД. Env остаётся только как значение для первого запуска; если значение в БД задано, оно приоритетнее env.
- **NginxionS фиксирует.** Значение задаёт NginxionS, администратору его менять не нужно (часто ради local-first).

Изменение настройки из GUI, которая читается в `envs.sh`/`start.sh` при старте, требует перезапуска процесса. Значения хранятся в БД (`system.env`), backend пишет их в `/data/nginxions/runtime.env`, `envs.sh` принимает из него только известные имена со значением своего формата (неверная строка не может остановить контейнер). Перезапуск делает сам NginxionS через `nginxions-control` (кнопка «Сохранить и перезапустить»), а не администратор.

## NPMplus (контейнер `nginxions`)

| Переменная | Upstream по умолчанию | NginxionS по умолчанию | Класс | Фаза |
|---|---|---|---|---|
| `TZ` | — (обязательна) | `UTC` | GUI (Администрирование → Настройки → Общие) | 4 ✅ |
| `PUID`, `PGID` | `0` | `0` | Bootstrap | — |
| `HTTP_PORT`, `HTTPS_PORT`, `NPM_PORT`, `GOA_PORT` | 80, 443, 81, 91 | те же; внешние порты — `NGINXIONS_*_PORT` | Bootstrap | — |
| `IPV4_BINDING`, `IPV6_BINDING`, `NPM_*_BINDING`, `GOA_*_BINDING`, `*_LISTEN_LOCALHOST` | все адреса | те же | Bootstrap | — |
| `DISABLE_IPV6` | `false` | `NGINXIONS_DISABLE_IPV6`, `true` (только IPv4; `false` включает IPv6) | Bootstrap | — |
| `DISABLE_HTTP`, `DISABLE_H3_QUIC`, `ENABLE_MPTCP`, `NGINX_QUIC_BPF` | `false` | `false` | GUI (Администрирование → Настройки → Сеть) | 4 ✅ |
| `LISTEN_PROXY_PROTOCOL_HTTP`, `LISTEN_PROXY_PROTOCOL_HTTPS` | `false` | `false` | GUI (Администрирование → Настройки → Сеть) | 4 ✅ |
| `DB_POSTGRES_*` | — (SQLite) | Postgres из compose, пароль из `DB_POSTGRES_PASSWORD_FILE` | Bootstrap | 0 ✅ |
| `DB_MYSQL_*` | — | не используется | Bootstrap (поддержка upstream сохраняется) | — |
| `COOKIE_SECRET` | случайный при каждом старте | `COOKIE_SECRET_FILE` от `nginxions-init` ✅ | Bootstrap (секрет) | 0 |
| `INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_PASSWORD` | — | не задаём: первый админ создаётся мастером в GUI | Bootstrap | — |
| `ACME_SERVER`, `ACME_EMAIL`, `ACME_EAB_KID`, `ACME_EAB_HMAC_KEY`, `ACME_PROFILE`, `ACME_SERVER_TLS_VERIFY` | Let's Encrypt | Аккаунт регистрируется при первом запросе сертификата, при старте обращений нет ✅ | GUI (Администрирование → Настройки → ACME → «ACME-серверы»): несколько серверов (Let's Encrypt, его staging, ZeroSSL, Google Trust Services, SSL.com, ТЦИ / НУЦ Минцифры (stage) или свой directory), у каждого email, EAB, профиль, проверка TLS и клиент certbot или lego; один — по умолчанию. Значения env прежних версий становятся первым сервером при старте | 6 ✅ |
| `ACME_RENEW`, `ACME_RENEW_DAYS` | продление вкл., окно certbot | — | GUI (Настройки → ACME) | 6 ✅ |
| `ACME_KEY_TYPE`, `ACME_KEY_SIZE`, `ACME_MUST_STAPLE`, `ACME_OCSP_STAPLING` | | те же | env (редко нужны) | 6 |
| `CUSTOM_OCSP_STAPLING` | `false` | `false` | GUI (Сертификаты) | 6 |
| `CERTBOT_RUN_INTERVAL` | 3 ч | 3 ч | GUI (Сертификаты) | 6 |
| `DEFAULT_CERT_ID` | 0 | 0 | GUI (Администрирование → Настройки → Общие) | 4 ✅ |
| `ECH_ROTATION_INTERVAL` | 1 ч | 1 ч | GUI (Сертификаты) | 6 |
| `NGINX_WORKER_PROCESSES`, `NGINX_WORKER_CONNECTIONS`, `NGINX_LOG_NOT_FOUND` | auto, 512, false | те же | GUI (Администрирование → Настройки → Nginx) | 4 ✅ |
| `NGINX_FORCE_X25519MLKEM768`, `NGINX_DISABLE_TLS12`, `NGINX_TRUST_SECPR1`, `NGINX_TRUST_RSA_PKCS1` | | те же | GUI (Администрирование → Настройки → TLS) | 4 ✅ |
| `DISABLE_NGINX_BEAUTIFIER` | `false` | `false` | NginxionS фиксирует | — |
| `NGINX_LOAD_OPENAPPSEC_ATTACHMENT_MODULE` | `false` | `true` (`NGINXIONS_WAF_ENABLED`) | GUI (Агенты → Агент open-appsec: «Включить WAF»), значение из БД пишется в `/data/nginxions/runtime.env` | 1 ✅ |
| `NGINX_LOAD_NJS_MODULE`, `NGINX_LOAD_GEOIP2_MODULE`, `NGINX_LOAD_LDAP_MODULE`, `NGINX_LOAD_NTLM_MODULE`, `NGINX_LOAD_VHOST_TRAFFIC_STATUS_MODULE` | `false` | `false` | GUI (Администрирование → Настройки → Nginx) | 4 ✅ |
| `TRUST_CLOUDFLARE` | `false` | `false` (загрузка IP-диапазонов Cloudflare — только при явном включении) | GUI (Администрирование → Настройки → Сеть, помечено «интернет») | 4 ✅ |
| `DISABLE_GRAVATAR` | `false` | **`true`** ✅ | NginxionS фиксирует: Gravatar убран, аватары с gravatar.com не загружаются | — |
| `NGINXIONS_CHECK_VERSION` | — (проверка всегда включена) | **`false`** ✅ | GUI (Администрирование → Настройки → Внешние сервисы) | 4 ✅ |
| `LOGROTATE`, `LOGROTATIONS` | `false`, 3 | **`true`** (логи нужны CrowdSec и аналитике), 3 | NginxionS фиксирует `LOGROTATE`; `LOGROTATIONS` — GUI (Администрирование → Настройки → Журналы) | 4 ✅ |
| `GOA`, `GOACLA` | `false` | `false` | Заменяется аналитикой NginxionS (Аналитика) | 4 ✅ |
| `PHP83`, `PHP84`, `PHP85` | `false` | `false` | PHP нет в образе NginxionS; если понадобится — GUI | позже |
| `INITIAL_DEFAULT_PAGE` | `congratulations` | то же | NginxionS фиксирует (настройка «страница по умолчанию» уже есть в GUI upstream) | — |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_DOMAIN`, `OIDC_REQUIRE_VERIFIED_EMAIL`, `OIDC_DISABLE_PASSWORD` | — | — | GUI (Администрирование → Вход через OIDC) | 3 |
| `AUTH_REQUEST_*_UPSTREAM` (Anubis, Tinyauth, oauth2-proxy, VoidAuth, Authelia, Authentik) | — | — | GUI (Безопасность → Внешняя аутентификация) | позже |
| `ENABLE_PRERUN` | `false` | `false` | NginxionS фиксирует (скрипты до запуска противоречат «всё через GUI») | — |
| `NODE_TLS_REJECT_UNAUTHORIZED` | — | — | Не используется; доверенные CA для OIDC/ACME добавляются в GUI | 6 |
| `REGENERATE_ALL` | — | — | Кнопка «Пересоздать конфигурацию» в Обзор → Сервисы | 1 ✅ |
| `NC_AIO`, `NC_DOMAIN` | — | — | Интеграция Nextcloud AIO upstream; не трогаем | — |

## Агент open-appsec (контейнер `openappsec`)

| Переменная | NginxionS | Класс | Фаза |
|---|---|---|---|
| `AGENT_TOKEN` | **не задаётся** (hybrid-режим без облака) | NginxionS фиксирует | 0 ✅ |
| `user_email` | не задаётся | NginxionS фиксирует | 0 ✅ |
| `autoPolicyLoad` | `true` (агент сам применяет `local_policy.yaml`, который генерирует NginxionS) | NginxionS фиксирует | 0 ✅ |
| `nginxproxymanager` | не задаётся (только помечает отчёт агента в облако) | NginxionS фиксирует | 1 ✅ |
| `SHARED_STORAGE_HOST`, `TUNING_HOST` | `127.0.0.1:7811`, `127.0.0.1:7813` (сервисы в том же контейнере; порт — патч 0004 агента) | Bootstrap | 0 ✅ |
| `https_proxy` | не задаётся | GUI (Система → Внешние сервисы), только если администратор включит онлайн-функции | 4 |
| `CROWDSEC_ENABLED`, `CROWDSEC_MODE`, `CROWDSEC_API_URL`, `CROWDSEC_AUTH_METHOD`, `CROWDSEC_AUTH_DATA` (встроенная интеграция агента) | выключено; LAPI `crowdsec:8080`, ключ bouncer `appsec` от `nginxions-init` | GUI (Агенты → Агент open-appsec → «Репутация IP из CrowdSec»); `nginxions-entry.sh` образа агента выставляет их из `nginxions-agent.env` | 1 ✅ |
| Advanced ML-модель | файл `/advanced-model/open-appsec-advanced-model.tgz` (том `appsec-model`) | Загрузка файла в GUI (Агенты → Агент open-appsec) | 1 ✅ |
| Fail-open/fail-close attachment и тайм-аут ответа агента (`agent.failOpenState.nginxModule`, `agent.failOpenTimeout.nginxModule` в `settings.json` агента) | fail-open, 50 мс | GUI (Агенты → Агент open-appsec) | 1 ✅ |
| Уровень отладки агента | по умолчанию | GUI (Система → Диагностика) | 4 |

Режим (prevent/detect), `minimum-confidence`, практики, триггеры и исключения — это не env, а `local_policy.yaml`. Его целиком генерирует NginxionS из своей БД (фазы 1 и 5).

## Сервисы обучения open-appsec

| Сервис | Переменная | NginxionS | Класс |
|---|---|---|---|
| tuning (в `openappsec`) | `QUERY_DB_HOST`, `QUERY_DB_USER` | `postgres`, роль `appsec` (CREATEDB) | Bootstrap |
| tuning (в `openappsec`) | `QUERY_DB_PASSWORD` | `QUERY_DB_PASSWORD_FILE`, читает `nginxions-openappsec.sh`, секрет от `nginxions-init` | Bootstrap (секрет) ✅ |
| tuning, shared storage (в `openappsec`) | `SERVER_PORT`, `SHARED_STORAGE_HOST` | 7813 и 7811 на 127.0.0.1 (задаёт `nginxions-openappsec.sh`) | Bootstrap |

`appsec-smartsync` (централизованное обучение нескольких агентов) убран из стека: в локальном режиме без регистрации у агента нет Fog-токена, поэтому выгрузка `CentralizedData` в него падала с «Access token is missing», и сервис простаивал. Агент учится локально; разметку NginxionS он читает из `tuning/decisions.data` shared-storage напрямую. Подробно — `docs/adr/0011-learning.md`.

## CrowdSec (`crowdsec`, официальный образ `crowdsecurity/crowdsec`)

Тома конфигурации и данных при первом старте наполняет `nginxions-init` из офлайн-снимка hub, встроенного в образ NginxionS.


| Переменная | NginxionS | Класс | Фаза |
|---|---|---|---|
| `DISABLE_ONLINE_API` | **`true`** (без CAPI: никаких сигналов наружу и community blocklist) | NginxionS фиксирует: CAPI не включается, его заменяют локальные блок-листы и обмен решениями между узлами (CrowdSec → Блок-листы) | 7 ✅ |
| `NO_HUB_UPGRADE` | `true` | NginxionS фиксирует; hub обновляется из GUI (CrowdSec → Hub: загрузка снимка, онлайн — только опцией) | 7 ✅ |
| `cscli.__hub_url_template__` (config.yaml, config.yaml.local) | `http://nginxions:7480/.nginxions/crowdsec-hub/%s/%s` — индекс hub отдаёт NginxionS (внутренний порт, не публикуется), не CDN | NginxionS фиксирует | 7 ✅ |
| `cscli.hub_branch` (config.yaml) | `master` (не спрашивать version.crowdsec.net) | NginxionS фиксирует | 0 ✅ |
| Ключ bouncer `nginxions` | файл `/run/secrets/bouncer_key_nginxions` от `nginxions-init` (штатный механизм образа) | Bootstrap (секрет) ✅ | 0 |
| Машина NginxionS (`crowdsec_machine_password`, `crowdsec_registration_token`) | секреты `nginxions-init`; машина регистрируется через `auto_registration` | Bootstrap (секрет) ✅ | 7 |
| `/data/crowdsec/crowdsec.conf` (Lua-баунсер NPMplus) | генерирует NginxionS | GUI (CrowdSec → Настройки → Баунсер NginxionS) | 7 ✅ |
| `COLLECTIONS`, `PARSERS`, `SCENARIOS`, `POSTOVERFLOWS` (+`DISABLE_*`) | не задаются; базовый набор во встроенном снимке hub | GUI (CrowdSec → Hub) | 7 ✅ |
| `ENROLL_KEY`, `ENROLL_INSTANCE_NAME`, `ENROLL_TAGS` | не задаются (без app.crowdsec.net) | NginxionS фиксирует | 0 ✅ |
| `USE_WAL` | `true` | NginxionS фиксирует | — |
| `TZ` | общий с NginxionS | GUI | 4 |
| Источники логов (`acquis.d`), профили, белые списки, AppSec, уровень журнала, `auto_registration` | файлы NginxionS в томе `crowdsec-conf` (`acquis.d/nginxions.yaml`, `profiles.yaml`, `nginxions-allowlist.yaml`, `nginxions-openappsec-prevent.yaml`, `config.yaml.local`) | GUI (CrowdSec → Настройки) | 7 ✅ |

## Compose-уровень (нельзя изменить из GUI)

Задаются один раз в `deploy/compose.yaml` и меняются только при обновлении NginxionS:

- сети `edge` и `internal` (у второй нет выхода в интернет);
- `openappsec` владеет сетью и IPC (`ipc: shareable`, опубликованные порты), `nginxions` подключается к ним (`network_mode`/`ipc: service:openappsec`); tmpfs-том `appsec-shm`;
- общие тома: `appsec-localconfig` (политика), `appsec-logs` (события, только чтение для NginxionS и CrowdSec), логи nginx для CrowdSec, `crowdsec-conf` и `crowdsec-data` в `nginxions` (настройки CrowdSec из GUI, список машин и баунсеров);
- метки `nginxions.managed=true`, по которым `nginxions-control` решает, чем можно управлять; сокет Docker смонтирован только в `openappsec`, где работает `nginxions-control` со своим белым списком операций;
- образы и версии (`deploy/.env`): `NGINXIONS_REGISTRY`, `NGINXIONS_VERSION`, `CROWDSEC_VERSION`, `POSTGRES_VERSION`.

## Обращения наружу только по действию администратора

При обычной работе NginxionS не выходит в интернет (это проверяет тест закрытого контура). Следующие обращения происходят только после явного действия в GUI. В GUI они должны быть помечены как «требует интернет»:

| Действие | Куда | Фаза, в которой довести до local-first |
|---|---|---|
| Запрос и продление ACME-сертификата (первый запрос регистрирует аккаунт) | ACME-сервер сертификата (Настройки → ACME), для ZeroSSL — api.zerossl.com | 6: свой ACME-сервер/PKI как локальная альтернатива |
| DNS-challenge: установка DNS-плагина certbot (`pip install` при первом использовании провайдера) | PyPI | 6: предустановленные плагины для популярных провайдеров или загрузка wheel через GUI |
| «Проверить доступность» домена при выпуске сертификата | site24x7.com | 6: проверка без внешнего сервиса или явное предупреждение |
| OCSP stapling (`ACME_OCSP_STAPLING`, `CUSTOM_OCSP_STAPLING`) | OCSP-респондеры CA | 6 |
| Вход через OIDC | указанный IdP (рекомендуется локальный) | 3 |
| Проверка обновлений, Gravatar, IP-диапазоны Cloudflare | api.github.com, gravatar.com, cloudflare.com | выключены по умолчанию ✅ |
