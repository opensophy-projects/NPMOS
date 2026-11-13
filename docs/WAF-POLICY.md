# Политика WAF NginxionS: полностью рабочий v1beta2

Документ описывает, какую политику open-appsec NginxionS должен поддерживать полностью. Каждое поле схемы
либо работает в агенте NginxionS, либо отклоняется проверкой в GUI с понятной причиной. Ни одно поле не
должно молча игнорироваться. План работ — фаза 11 в [ROADMAP.md](ROADMAP.md). Текущее устройство политики
описано в [ADR-0008](adr/0008-waf-policy.md).

## 1. Почему это нужно

open-appsec описывает локальную политику в двух синтаксисах:

- **v1beta1** — исходный, на нём работал open-appsec-npm (интеграция в NPM/NPMplus);
- **v1beta2** — новый, в документации помечен как beta.

Схема v1beta2 (`schema-v1beta2.json`, взята у агента) шире того, что агент применяет на самом деле. Сейчас
v1beta2 работает так:

- часть полей агент читает, но в конфигурацию движков не передаёт;
- часть движков есть только в Premium-версии или требует облака Check Point;
- некоторые сочетания полей молча теряются.

В NPMplus с open-appsec-npm политика правилась сырым YAML без проверки. Такие поля просто не работали, и
администратор об этом не узнавал.

NginxionS генерирует политику из своей БД (ADR-0008). Поэтому гарантия нужна на нашей стороне: то, что можно
выбрать в GUI, действительно применяется агентом.

## 2. Как устроено сейчас

- Объекты хранятся в терминах v1beta2. В агент файл уходит:
  - в v1beta1, если политика не использует возможностей только v1beta2;
  - иначе в v1beta2. Такие возможности: ограничения частоты, ответ-перенаправление, IPS, File Security
    (`objects/format.js`, `needsV2`).
- Генератор обходит известные ограничения агента:
  - у практики с ограничениями частоты в каждом следующем правиле своя копия `<практика>.<n>`;
  - защиты «как у правила» в v1beta1 получают копию практики `<практика>.<режим>`;
  - практика ограничения частоты, которая ничего не ограничивает, не пишется в правило по умолчанию.
- Что уже исправлено в коде агента (`openappsec/agent`, метка `NginxionS:`):
  - **все** исключения правила, а не только первое — в обоих синтаксисах;
  - защиты CSRF, раскрытия ошибок и открытого перенаправления;
  - `nonValidHttpMethods`;
  - список `syslogService`/`cefService` из схемы;
  - правило ограничения частоты без `action`/`match` больше не отбрасывается целиком;
  - ограничение частоты для хоста без схемы;
  - стабильные ID ответов (страница блокировки);
  - нейтральные тексты страницы блокировки;
  - конвертер Snort на Node.js (в образе нет Python).

Комментарий в начале `objects/format.js` («v1beta2 применяет только первое исключение») устарел: агент
NginxionS применяет все исключения в обоих синтаксисах.

## 3. Аудит v1beta2 по коду агента

Источник — `openappsec/agent/components/security_apps/local_policy_mgmt_gen`: разбор
`new_*.cc` и генерация конфигурации движков `policy_maker_utils.cc`, `*_section.cc`. Кроме того —
компоненты `waap`, `rate_limit`, `ips` и `utils/generic_rulebase`.

Статусы:

- ✅ — работает;
- 🟡 — работает с ограничением;
- ❌ — агент читает поле, но не применяет;
- ⛔ — движка нет в агенте NginxionS или ему нужно облако Check Point;
- ➖ — относится только к Kubernetes или облаку и в NginxionS не нужно.

### 3.1. `policies` (default и specificRules)

| Поле | Статус | Что на самом деле |
|---|---|---|
| `host` | ✅ | `хост[/путь]`. Правило без `host` — `*` |
| `mode` | 🟡 | Обязателен: без `mode` агент бросает исключение `mode invalid` (`new_appsec_policy_crd_parser.cc`) |
| `threatPreventionPractices` | 🟡 | Ключ обязателен. Берётся **только первая** практика списка (`extractAnnotationsNames`, «TBD: support multiple practices»). Пустой список — практика правила по умолчанию |
| `accessControlPractices` | 🟡 | То же: ключ обязателен, применяется только первая практика |
| `triggers` | 🟡 | Применяется только первый триггер журналирования |
| `customResponse` | ✅ | Если поле не задано, агент подставляет имя `"403"`. Такого объекта нет, поэтому действует встроенный ответ 403 |
| `exceptions` | ✅ | Все исключения (исправлено в NginxionS) |
| `sourceIdentifiers` | ✅ | |
| `trustedSources` | 🟡 | Работают, **только если у того же правила задан `sourceIdentifiers`**. Иначе список доверенных источников молча пуст (`createTrustedSourcesSection`) |
| `specificRules[].name` | ➖ | Агент не читает. NginxionS использует имя для своих правил |
| `appsecClassName`, `policyActivations` | ➖ | Только Kubernetes |
| `autoUpgrade` | ➖ | Автообновление агента из облака |

### 3.2. `threatPreventionPractices`

| Поле | Статус | Что на самом деле |
|---|---|---|
| `practiceMode`, `webAttacks.overrideMode` | ✅ | `inherited` — режим правила |
| `webAttacks.minimumConfidence` | ✅ | |
| `webAttacks.maxUrlSizeBytes`, `maxObjectDepth`, `maxBodySizeKb`, `maxHeaderSizeBytes` | ✅ | `PracticeAdvancedConfig` |
| `webAttacks.protections.csrfProtection`, `errorDisclosure`, `openRedirect` | ✅ | Исправлено в NginxionS |
| `webAttacks.protections.nonValidHttpMethods` | ✅ | Исправлено в NginxionS |
| `snortSignatures.files` | 🟡 | Работает (конвертер на Node.js), но берётся **только первый файл** (`getFiles()[0]`) |
| `snortSignatures.configmap` | ➖ | Kubernetes |
| `intrusionPrevention.*` | ⛔ | Конфигурация генерируется, но сигнатуры Check Point IPS приходят ресурсом из облака (`registerExpectedResource("IPS", "protections")`). В закрытом контуре их нет, и IPS ничего не проверяет |
| `fileSecurity.*` | ⛔ | Секция генерируется, но компонента File Security в агенте с открытым кодом нет |
| `schemaValidation.*` | ⛔ | Агент только собирает данные для обновления схемы. Проверки запросов по OpenAPI в открытом коде нет |
| `antiBot.*` | ⛔? | В WAAP есть внедрение скрипта (`Waf2Engine.cc`), но по документации open-appsec это Premium. Работу без облака нужно проверить на стенде |

### 3.3. `accessControlPractices` (ограничение частоты)

| Поле | Статус | Что на самом деле |
|---|---|---|
| `practiceMode`, `rateLimit.overrideMode` | ✅ | |
| `rules[].uri`, `limit`, `unit` (`minute`/`second`) | ✅ | |
| `rules[].triggers` | 🟡 | Работает, только если триггер правила политики назван и в правиле ограничения частоты |
| `rules[].action` | ❌ | Генератор не читает поле. Действие всегда берётся из режима практики, хотя движок `rate_limit` действие правила поддерживает |
| `rules[].condition` | ❌ | Генератор не читает поле и не пишет `match`, хотя движок поддерживает `match` |
| `rules[].comment` | ✅ | Только текст |
| одна практика в нескольких правилах | 🟡 | Агент хранит ограничение частоты по имени практики, поэтому действует последнее правило. Генератор NginxionS делает копии |
| ответ при превышении | ❌ | Генератор не пишет `webUserResponseId`. Отвечает встроенный ответ движка, а не `customResponse` правила |

Счётчик ограничения частоты ведётся по идентификатору источника правила (`sourceIdentifiers`), без него — по IP.

### 3.4. `customResponses`

| Поле | Статус | Что на самом деле |
|---|---|---|
| `mode: response-code-only`, `httpResponseCode` | ✅ | |
| `mode: block-page`, `messageTitle`, `messageBody` | ✅ | Стабильные ID и нейтральные тексты — исправлено в NginxionS |
| `mode: redirect`, `redirectUrl`, `redirectAddXEventId` | ❌ | Поля прочитаны (`new_custom_response.cc`), но в секцию `WebUserResponse` не передаются: генератор пишет только код, заголовок и текст. Движок (`WebTriggerConf`) перенаправление умеет: ключи `redirect URL`, `xEventId`. **Сейчас перенаправление не работает** |

### 3.5. `logTriggers`

| Поле | Статус | Что на самом деле |
|---|---|---|
| `accessControlLogging.*`, `appsecLogging.*`, `extendedLogging.*` | ✅ | |
| `additionalSuspiciousEventsLogging.enabled`, `minSeverity`, `responseBody` | ✅ | |
| `additionalSuspiciousEventsLogging.responseCode` | ❌ | Прочитано, но в секцию триггера не передаётся |
| `logDestination.cloud` | ➖ | В hybrid-режиме агент принудительно ставит `false`. NginxionS тоже всегда пишет `false` |
| `logDestination.local-tuning`, `logToAgent`, `stdout.format` | ✅ | NginxionS читает журналы агента и `local-tuning` |
| `logDestination.syslogService`, `cefService` | 🟡 | Только **первый** сервис списка, только UDP (`proto` игнорируется), только IPv4-адрес |
| `k8s-service` | ➖ | Kubernetes |

### 3.6. `exceptions`

| Поле | Статус | Что на самом деле |
|---|---|---|
| `action`: `accept`, `drop`, `skip`, `suppressLog` | ✅ | `drop` → reject, `skip` → ignore, `suppressLog` → без записи в журнал |
| `condition[].key` | 🟡 | Генератор знает только 9 ключей: `countryCode`, `countryName`, `hostName`, `paramName`, `paramValue`, `protectionName`, `sourceIdentifier`, `sourceIp`, `url`. Остальные молча отбрасываются. Движок WAAP сопоставляет и другие: `method`, `headerName`, `headerValue`, `paramLocation`, `indicator`, `keyword`, `responseCode`, `responseBody` (по коду; проверить на стенде) |
| логика условий | 🟡 | Значения одного ключа — ИЛИ, разные ключи — И. Отрицания нет, хотя движок умеет `not-equals`, `not-in`, `exist` (`match_query.cc`). Значения динамических ключей (`url`, `paramName`…) — регулярные выражения |

### 3.7. `trustedSources`, `sourcesIdentifiers`

| Поле | Статус | Что на самом деле |
|---|---|---|
| `trustedSources.minNumOfSources`, `sourcesIdentifiers` | 🟡 | См. 3.1: без `sourceIdentifiers` у правила список пуст |
| `sourcesIdentifiers[].identifier` (`headerkey`, `JWTKey`, `cookie`, `sourceip`, `x-forwarded-for`) и `value` | ✅ | `JWTKey` → заголовок `authorization` |

## 4. Решение

**Формат.** Остаёмся на `apiVersion: v1beta2` open-appsec и доводим агент так, чтобы v1beta2 работал
полностью. Отдельный синтаксис не вводим:

- импорт и экспорт остаются совместимыми с документацией open-appsec и с файлами других установок;
- пример из документации open-appsec у нас работает так, как в нём написано.

Своё расширение схемы добавляем только там, где в v1beta2 нет нужной возможности, а движок агента её
умеет (раздел 5.2):

- поле расширения необязательное и отмечено в `schema-v1beta2.json` как `x-nginxions`;
- агент с исходным кодом open-appsec такие поля игнорирует (неизвестные ключи cereal пропускает);
- экспорт «совместимый v1beta2» убирает их с предупреждением.

**Правило «нет молчаливых полей».** Каждое поле схемы попадает в одну из трёх групп:

1. Работает: агент NginxionS применяет поле так, как описано в документации.
2. Отклоняется: проверка политики (предпросмотр, импорт, API) возвращает ошибку с причиной. Сюда
   относятся File Security, Schema Validation, IPS Check Point, а также Anti-Bot, пока он не проверен.
   В GUI такие движки не показываются (сейчас — с пометкой «Premium»).
3. Kubernetes или облако (`configmap`, `appsecClassName`, `policyActivations`, `cloud`, `k8s-service`,
   `autoUpgrade`): допускаются при импорте и выбрасываются с предупреждением.

**Один формат файла для агента.** Генератор всегда пишет v1beta2. Ветка v1beta1 и копии
`<практика>.<режим>` для защит удаляются. v1beta1 остаётся для импорта (open-appsec-npm, старые экспертные
фрагменты) и как формат экспорта.

**Одна практика каждого вида и один триггер на правило.** «Несколько практик в правиле» в агенте не
реализовано, а слияние двух практик неоднозначно: какой порог уверенности, какой лимит размера. Поэтому:

- проверка требует ровно одну практику threat prevention, одну практику access control и один триггер
  журналирования;
- импорт с несколькими элементами показывает в плане, что применится только первый, и предлагает объединить.

## 5. Целевая политика

### 5.1. Доработки агента (`openappsec/agent`, метка `NginxionS:`)

| # | Что | Где |
|---|---|---|
| A1 | Ответ-перенаправление: `redirectUrl` → `redirect URL`, `redirectAddXEventId` → `xEventId` в секции `WebUserResponse` | `triggers_section.cc`, `policy_maker_utils.cc` (`extractWebUserResponseTriggerSectionrData`) |
| A2 | Ограничение частоты: `rules[].action` → `action` правила; `rules[].condition` → `match` (ключи `sourceIP`, `url`, `method`, `headerName`/`headerValue`; список — после проверки движка) | `access_control_practice.cc` |
| A3 | Ответ при превышении частоты — `customResponse` правила: `webUserResponseId` в секции `rateLimit` | `access_control_practice.cc`, `createRateLimitSection` |
| A4 | Доверенные источники без `sourceIdentifiers` у правила — по IP источника (`sourceip`), а не пустой список | `createTrustedSourcesSection<V1beta2>` |
| A5 | Ограничение частоты хранится по ассету, а не по имени практики: одна практика в нескольких правилах работает без копий | `createRateLimitSection` (ключ `rate_limit`) |
| A6 | Snort: все файлы `snortSignatures.files` (объединение в один набор), а не только первый | `createSnortSections` |
| A7 | `additionalSuspiciousEventsLogging.responseCode` передаётся в триггер | `extractLogTriggerData`, `LogTriggerSection` |
| A8 | Syslog/CEF: все сервисы списка, `proto: tcp/udp`, адрес — имя или IPv6 (если это поддерживает компонент журналирования агента; иначе — проверка в GUI) | `new_log_trigger.cc`, `triggers_section.cc` |
| A9 | Правило без `mode` — режим правила по умолчанию, а не исключение | `new_appsec_policy_crd_parser.cc` |
| A10 | Unit-тесты генератора на каждый пункт (вход — `local_policy.yaml`, выход — секции конфигурации); сейчас генератор почти без тестов (`LCOV_EXCL`) | `local_policy_mgmt_gen/*_ut` (ctest в сборке образа) |

### 5.2. Расширения схемы NginxionS (`x-nginxions`)

Добавляются только поверх доработок A1–A10 и только на то, что движок уже умеет:

| Поле | Что даёт |
|---|---|
| `exceptions[].condition[].key`: `method`, `headerName`, `headerValue`, `paramLocation`, `indicator` | Исключения по методу, заголовку, месту параметра, индикатору атаки. Сейчас такие условия отбрасываются |
| `exceptions[].condition[].op`: `equals` (по умолчанию), `not-equals`, `in`, `not-in`, `exist` | Отрицание: «всё, кроме…», например drop для всех стран, кроме RU |
| `customResponses[].headers` (если позволяет attachment) | Заголовки ответа блокировки, например `Retry-After` для 429 |

Каждое расширение сначала проверяется на стенде: какие ключи на самом деле сопоставляет WAAP, а какие
только объявлены. До проверки поле в схему не входит.

### 5.3. Генератор и проверка (backend NginxionS)

- `format.js`:
  - всегда `asV2`;
  - удалить `needsV2`, `resolveProtections` и выбор v1beta1 в `policy.js`;
  - экспорт v1beta1 остаётся с предупреждениями о том, что теряется.
- `model.js`: проверка «нет молчаливых полей» по разделу 4, ошибки с путём поля и причиной.
- Проверка ссылок:
  - `trustedSources` без `sourceIdentifiers` — предупреждение, пока не сделан A4;
  - несколько практик или триггеров в правиле — ошибка.
- Снимок применённой политики: после применения NginxionS сравнивает, что агент записал в
  `/etc/cp/conf/*/*.policy` (секции `rulebase`), с ожидаемым. Расхождение показывается в статусе агента.
  Это ловит новые молчаливые поля при обновлении open-appsec.

### 5.4. GUI

- Редактор объектов показывает только рабочие поля. Движки Premium и облака не показываются вовсе (сейчас —
  с пометкой «Premium»).
- Новые поля в редакторе:
  - перенаправление (URL, X-Event-ID);
  - действие и условия правила ограничения частоты;
  - ответ при превышении частоты;
  - несколько файлов Snort;
  - несколько syslog/CEF с протоколом;
  - расширенные условия исключений.
- Импорт показывает в плане по каждому полю «применится», «отброшено (Kubernetes/облако)» или «ошибка».

## 6. Приёмка

- Unit-тесты агента (ctest): на каждое поле раздела 3 — ожидаемая секция конфигурации.
- Unit-тесты backend: проверка «нет молчаливых полей», импорт примеров open-appsec
  (`objects/examples`), экспорт v1beta1.
- Smoke (`deploy/test/smoke.sh`) на живом агенте без интернета:
  - перенаправление: код 302 и `Location` (+ `X-Event-ID`);
  - правило ограничения частоты с условием `url` и своим действием (detect не блокирует, prevent
    блокирует), ответ — `customResponse` правила;
  - одна практика ограничения частоты в двух хостах — работают обе;
  - доверенные источники без идентификатора источника;
  - два файла Snort — срабатывают сигнатуры из обоих;
  - исключение с отрицанием (если расширение принято);
  - событие с `responseCode` в журнале.
- Пример `local_policy.yaml` из документации open-appsec импортируется без молчаливых потерь. Всё, что не
  применится, перечислено в плане импорта.
