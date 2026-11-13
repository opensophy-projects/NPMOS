# DevSecOps: проверки безопасности в CI

Все проверки идут внутри GitHub Actions. Ни один инструмент не требует аккаунта на другом сайте: каждый запускается
в задаче из образа, закреплённого по версии и digest (`.github/security/tools.env`). Результаты остаются в GitHub.

## Как включить (шпаргалка)

| Что нужно | Как |
|---|---|
| Быстрые проверки | ничего: идут на каждый push в любую ветку |
| Полная проверка (образы, закрытый контур, DAST) | push в `work` или тег `v*`, любой PR, `[full]` в сообщении коммита, либо Actions → CI → Run workflow → уровень `full` |
| Расширенная проверка (тяжёлые сканеры) | метка `security-scan` на PR, либо ветка `security/<что угодно>`, либо Actions → CI → Run workflow → уровень `extended` |
| Еженедельный отчёт | сам, по понедельникам (`security-weekly.yml`); вне расписания: Actions → Weekly security → Run workflow |
| Где смотреть итог | Summary прогона и артефакт `security-report`; еженедельный — issue с меткой `security` |

Подробнее о глубинах — в разделе [Когда запускается](#когда-запускается).

## Что проверяется

| Категория | Инструмент | Что ищет | Где запускается |
|---|---|---|---|
| SAST | **Semgrep** | уязвимости JS/TS, Go, C/C++, Dockerfile и workflow: правила сообщества и правила NginxionS (`.github/security/semgrep.yml`) | `security.yml` |
| SAST | **CodeQL** (JS/TS, C/C++, Go, Actions) | путь данных от запроса до опасного вызова: инъекции, SSRF, XSS, обход путей; в агенте — работа с памятью и строками | `security.yml` |
| Секреты | **Gitleaks** | ключи, пароли и токены в файлах и во **всей истории** git | `security.yml` |
| SCA | **OSV-Scanner** | известные уязвимости зависимостей: npm backend и frontend, Go-модули агента (`openappsec/*/go.mod`); лицензии | `security.yml` |
| SBOM | **Syft** | состав исходников (backend, frontend) и каждого образа: CycloneDX и SPDX | `security.yml`, `ci.yml` |
| IaC | **hadolint**, **Trivy config**, **KICS** | Dockerfile, compose и workflow: root, лишние права, небезопасные приёмы | `security.yml` |
| CI/CD | **actionlint**, **zizmor**, **CodeQL Actions** | ошибки и уязвимости самих workflow: инъекции в `${{ }}`, права токена, кеш, непривязанные actions | `security.yml` |
| Цепочка поставок | **OpenSSF Scorecard** | практики репозитория (только ветка `work`) | `security.yml` |
| Образы | **Trivy** | уязвимости пакетов и секреты в слоях `nginxions` и `nginxions-openappsec` | `ci.yml` → `images` |
| Образы | **Grype** | второе мнение по SBOM образа | `ci.yml` → `images` |
| Образы | **Dockle** | CIS Docker Benchmark | `ci.yml` → `images` |
| DAST | **OWASP ZAP** | активная атака на API интерфейса по OpenAPI-схеме с сессией администратора; заголовки и cookies страниц интерфейса и сайта за прокси-хостом | `ci.yml` → `images` |
| DAST | **Nuclei** | известные CVE, открытые панели и файлы, ошибки конфигурации | `ci.yml` → `images` |
| TLS | **testssl.sh** | протоколы, шифры, HSTS, известные атаки на TLS — интерфейса (:81) и прокси-хоста (:443) | `ci.yml` → `images` |
| nginx | **gixy** | работающая конфигурация nginx (`nginx -T`): SSRF, инъекции заголовков, обход `alias` | `ci.yml` → `images` |
| Качество | **jscpd**, покрытие тестами | дублирование кода, покрытие backend (`node --test`), frontend (vitest) и Go-сервисов агента (`scripts/test-go.sh`) | `security.yml` |

Код агента NginxionS (`openappsec/`: агент, attachment, shared storage, tuning, smartsync) — наш код: его проверяют те
же сканеры (Semgrep, CodeQL C/C++ и Go, Gitleaks, OSV-Scanner, hadolint, Trivy config, KICS), и его высокие и
критические находки блокируют, как в остальном коде NginxionS. Части upstream, которые агент не собирает (примеры
деплоя, плагины других шлюзов, их Dockerfile), удалены, а не исключены из сканов.

К ним добавляются проверки, которые были и раньше: biome, tsc, тесты (backend, frontend, Go-сервисы агента —
`scripts/test-go.sh`), shellcheck, `compose config`, закрытый контур.

DAST (`scripts/test-dast.sh`) поднимает прод-стек, настраивает его как администратор в GUI (`deploy/test/dast-setup.sh`:
первый админ, корневой CA и серверный сертификат PKI NginxionS, прокси-хост `dast.local` с TLS, HTTP/2, HSTS и фильтром
эксплойтов) и атакует его из контейнеров той же сети. У каждого сканера свой адрес, поэтому бан CrowdSec одного сканера
не останавливает другие. Сканеры идут параллельно.

## Когда запускается

| Глубина | Что входит | Когда |
|---|---|---|
| **Быстрая** (~5–10 мин) | lint, типы, тесты, `security.yml`: Semgrep, CodeQL, Gitleaks, OSV-Scanner, SBOM исходников, IaC, workflow, качество | каждый push в любую ветку |
| **Полная** (~45 мин) | быстрая + сборка образов, закрытый контур, скан образов, DAST, шлюз перед публикацией | push в `work`, теги `v*`, pull request, кнопка Run workflow (уровень `full`), push с `[full]` в сообщении коммита |
| **Расширенная** (~1,5–2 ч) | полная + тяжёлые проверки (ниже) | ветки `security/**` (и еженедельная), pull request с меткой `security-scan`, кнопка Run workflow с уровнем `extended` |

Глубину выбирает первая задача CI («Depth of the run»), она же пишет её в Summary прогона.

**Что добавляет расширенная глубина.** Основной пайплайн она не нагружает: всё ниже выполняется только на ней.

| Где | Что |
|---|---|
| Semgrep | ещё наборы правил `p/owasp-top-ten`, `p/cwe-top-25`, `p/security-audit`, `p/nginx` (блокирует то же, что обычно: ошибки в нашем коде) |
| CodeQL | набор `security-and-quality`; запросы качества (без тега `security`) только показываются, не блокируют |
| Gitleaks | история всех веток и тегов, не только текущей |
| OWASP ZAP | полный активный скан страниц интерфейса и `dast.local` (`zap-full-scan`), скан API без ограничения в 20 минут (до 60) |
| Nuclei | ещё шаблоны `info` и шаблоны, которые `.nuclei-ignore` отключает по умолчанию (intrusive); без `dos` |
| Schemathesis | фаззинг API по схеме OpenAPI с сессией (15 минут, после остальных сканеров: меняет данные): ошибки 500 показываются, операция, отвечающая без аутентификации (ST401), блокирует. Токены и аутентификация учётных записей не трогаются, чтобы сессия жила |
| Контейнеры | `scripts/check-runtime.sh` на работающем стеке: `privileged`, пространства имён хоста, сокет Docker не у `nginxions-control` — блокируют; `cap_add`, нет `cap_drop: ALL` или `no-new-privileges`, root, запись в корень — показываются |
| Docker Hub | Trivy и Grype по опубликованным `develop`, `latest` и трём последним релизам `X.Y.Z` (новые CVE в выпущенном); если на Hub нет ни одного образа, проверка падает |

**Как запустить расширенную проверку**

- **PR:** поставьте на него метку `security-scan`. Скан идёт сразу и на каждый новый push, пока метка стоит; другие
  метки прогон не запускают и текущий не отменяют. Метку ставит только тот, у кого есть запись в репозиторий.
- **Кнопкой:** Actions → CI → Run workflow, выберите ветку и уровень `extended` (`full` — обычный полный, `fast` —
  только быстрые проверки).
- **Веткой:** любая ветка `security/…`.

**Каждую неделю** (понедельник, `security-weekly.yml`): от `work` создаётся ветка `security/<дата>`, и на ней
запускается расширенный CI. По итогам открывается issue «✅/❌ Отчёт безопасности <дата>» с меткой `security`: приходит
уведомление, видна история по неделям. Ветки старше 8 недель удаляются. Запустить вне расписания: Actions → Weekly
security → Run workflow.

Ветку, созданную токеном workflow, GitHub не запускает (защита от цепочек), поэтому `security-weekly.yml` сам
запускает CI на новой ветке.

## Что блокирует

Политика — одна, в начале `scripts/security-report.mjs`:

| Проверка | Блокирует |
|---|---|
| Semgrep, CodeQL | высокие и критические находки **в коде NginxionS** (`nginxions/backend/nginxions`, `nginxions/frontend/src/nginxions`, `openappsec`, `deploy`, `scripts`, `.github`); в коде upstream NPMplus — только в отчёт |
| Gitleaks | любая находка (примеры upstream исключены в `.github/security/gitleaks.toml` с причинами) |
| OSV-Scanner | высокие и критические, **если есть исправленная версия** |
| Trivy (образы) | высокие и критические с исправленной версией; секреты в слоях — высокие и критические |
| Dockle | FATAL |
| hadolint | ошибки в Dockerfile из `deploy/` |
| actionlint | любая ошибка |
| zizmor | high |
| ZAP | high при уверенности medium и выше |
| Nuclei, testssl.sh, gixy | высокие и критические |
| Grype, KICS, Trivy config, Scorecard, лицензии, качество | только в отчёт |

Ещё одна проверка: если проверка, которая должна была запуститься, не дала результата (шаг упал, файл не появился),
это тоже провал. Непрошедшая проверка — не «чисто».

Образы публикуются на Docker Hub только после шага `security gate`: с блокирующей находкой в образе или DAST ничего
не публикуется.

## Отчёт

- **Сводка прогона**: Actions → прогон → Summary, раздел «Отчёт безопасности NginxionS». Там итог, таблица всех
  проверок (сколько открытых критических, высоких, средних и низких находок, сколько ложных срабатываний и принятых
  рисков, что блокирует), блокирующие находки, ложные срабатывания, принятые риски, записи списка рисков, которые
  больше ничего не находят, SBOM, метрики качества и открытые находки по каждому инструменту.
- **Артефакт `security-report`** (внизу страницы прогона):
  - `security-report.html` — тот же отчёт страницей со всеми находками;
  - `security-report.md` — он же в Markdown;
  - `sbom/` — SBOM каждого состава: `source-backend`, `source-frontend`, `nginxions`, `nginxions-openappsec`;
  - `findings.json` — каждая находка с вердиктом (`open`, `blocking`, `false-positive`, `accepted`) и причиной: для
    скриптов и сравнения прогонов;
  - `raw/` — исходные результаты всех сканеров (SARIF, JSON; отчёты ZAP в HTML).
- **Security → Code scanning**: находки Semgrep, CodeQL, Gitleaks, OSV-Scanner, KICS, zizmor, Scorecard и Trivy с
  историей, фильтрами и привязкой к строкам кода.

## SBOM

Для каждого состава в артефакте лежат четыре файла:

| Файл | Зачем |
|---|---|
| `sbom/<состав>.html` | открыть в браузере: таблица компонентов, поиск, фильтр по экосистеме, кнопки «Скопировать список» и «Скачать CSV» |
| `sbom/<состав>.cdx.json` | CycloneDX 1.6 — для Dependency-Track, Grype, Trivy и других инструментов |
| `sbom/<состав>.spdx.json` | SPDX 2.3 — стандартный формат для передачи и аудита |
| `sbom/<состав>.csv` | для таблиц |

Составы: `source-backend` и `source-frontend` — зависимости исходников (frontend попадает в образ собранным, поэтому
его библиотеки видны только здесь); `nginxions` и `nginxions-openappsec` — всё, что есть в образе: пакеты Alpine, модули
Node.js, бинарники Go.

SBOM зависимостей репозитория также строит сам GitHub: Insights → Dependency graph → Export SBOM.

## Ложные срабатывания и принятые риски

Каждая находка либо исправляется, либо получает вердикт в `.github/security/accepted-risks.json`:

- **ложное срабатывание** (`"kind": "false-positive"`): это не уязвимость этого кода — инструмент ошибся или
  отмеченный путь данных задуман и безопасен; `reason` объясняет почему (чем проверено значение, какой тест это
  показывает);
- **принятый риск** (без `kind`): находка настоящая, но остаётся по указанной причине (нет исправления в Alpine,
  так устроено взаимодействие контейнеров, решение владельца репозитория) — до даты `until`.

```json
{
	"risks": [
		{
			"kind": "false-positive",
			"tool": "codeql-go",
			"id": "go/sql-injection",
			"where": "smartsync-tuning/internal/pkg/query/datatube.go",
			"reason": "значения запроса — литералы SQL (sqlLiteral), queries_nginxions_test.go проверяет кавычку в заголовке",
			"until": "2027-05-01"
		},
		{
			"tool": "trivy-nginxions",
			"id": "CVE-2026-12345",
			"where": "libfoo",
			"reason": "уязвимая функция не вызывается: модуль собран без X; исправление ждём в Alpine 3.25",
			"until": "2027-01-31"
		}
	]
}
```

`tool` — id проверки из `scripts/security-report.mjs` (`semgrep`, `codeql-js`, `codeql-cpp`, `codeql-go`, `osv`,
`trivy-nginxions`, `grype-nginxions`, `zap-api`…) или `*`; `id` — правило или CVE, `*` — любое (только вместе с
`where`); `where` — часть места или названия находки (необязательно); `"unfixed": true` — запись действует, только
пока у находки нет исправленной версии (пакеты Alpine): как только исправление появится, находка снова открыта. После
даты `until` находка снова блокирует, и решение нужно принять заново. Ложные срабатывания и принятые риски
показываются в отчёте отдельными разделами и считаются в сводке отдельно от открытых находок. Запись, которая в
прогоне ничего не нашла (находку исправили, код переехал), попадает в раздел «Записи без находок» и предупреждение
прогона: её удаляют или правят `where`.

Во вкладку **Security → Code scanning** GitHub они не попадают: перед загрузкой SARIF `scripts/sarif-accepted.mjs`
убирает из него принятые риски этого инструмента и находки, подавленные в коде (`// nosemgrep: <правило> -- почему`);
GitHub закрывает такие оповещения при следующем анализе. Сам GitHub читает подавления только у CodeQL, поэтому без
этого шага каждое принятое и подавленное оставалось бы открытым оповещением. Полные результаты остаются в артефактах
и в отчёте.

Как закрыты находки, которые были приняты раньше (их записи удалены из `accepted-risks.json`):

- **возможности контейнеров**: у каждого сервиса `cap_drop: ALL`; `nginxions` добавляет только `SETGID` (порты ниже
  1024 без `NET_BIND_SERVICE`: `sysctls` `net.ipv4.ip_unprivileged_port_start=0` у `openappsec`, владельца сети),
  `postgres` — пять, нужных его entrypoint; `openappsec`, `crowdsec`, `nginxions-init` — ни одной. У всех
  `no-new-privileges` и `healthcheck`; порты публикуются на `NGINXIONS_BIND_IP` / `NGINXIONS_ADMIN_BIND_IP`
  (по умолчанию `0.0.0.0`). Оверлеи `compose.dev.yaml` и `deploy/test/` повторяют это для своих сервисов;
- **Python и SQLite в образе агента**: сигнатуры Snort конвертирует `snort_to_ips_local.mjs` (Node.js образа), тест
  `snort_to_ips_local.test.mjs` сверяет его вывод с питоновским оригиналом upstream; из Boost ставятся только
  библиотеки, которые линкуют бинарники агента (`scanelf` в стадии сборки), а не пакет `boost`, тянувший
  `boost-python3`, Python и SQLite; сборка падает, если они всё же попали в образ;
- **Lua 5.1 в образе `nginxions`**: `cjson` собирается под LuaJIT, `lua-resty-http`/`lua-resty-openssl` берутся из
  git по коммиту (без luarocks);
- **IPC агента**: очереди в `/dev/shm` принадлежат пользователю и группе nginx и имеют права `0660`, сокеты агента —
  `0660` с группой `NGINXIONS_IPC_GID` (если задан), а не `0666`;
- **HSTS** на интерфейсе (81) и на сайте по умолчанию; в DAST интерфейс получает сертификат PKI NginxionS через
  «Настройки → Общие → сертификат по умолчанию», testssl проверяет цепочку от корня теста (`--add-ca`);
- **регулярное выражение правила mTLS** проверяется без компиляции в backend (`regexProblem`), с запретом вложенных
  повторений вида `(a+)+` (ReDoS в nginx);
- **`eval(` в бандле** (ZAP 10110): редактор кода подсвечивает только nginx, YAML, JSON, Bash и PHP
  (`src/nginxions/components/CodeEditor.tsx`), грамматики остальных ~300 языков Prism в бандл не попадают;
- **Dockerfile**: без `cd` в `RUN` (`git -C`, `make -C`, `WORKDIR`), `HEALTHCHECK` в dev-образе;
- **закрепление зависимостей** (Scorecard Pinned-Dependencies): образы CrowdSec, Node и NPMplus — по digest (тег
  CrowdSec CI сверяет с `deploy/.env`), certbot образа (`nginxions/certbot-requirements.txt`) и тренер модели
  (`model/requirements.txt`) ставятся `pip --require-hashes` со всеми зависимостями;
- **ответы API с ошибкой** (ZAP 100000, 90022): данные, которые отвергла база (несуществующий сертификат или список
  доступа, неверный тип, дубликат), — 400, а не 500; `Cache-Control: no-cache, no-store, must-revalidate` (ZAP 10015);
  лог интерфейса прогона DAST сохраняется в `dast/nginxions.log` артефакта;
- **сертификат PKI без отзыва** (testssl `cert_revocation`): при заданном в «PKI → Настройки» адресе NginxionS
  сертификаты называют свои CRL и OCSP; DAST задаёт его, как администратор;
- **провайдер покрытия vitest** — в `devDependencies` фронтенда (lockfile), а не ставится в задаче CI;
- **лицензия** — `LICENSE` в корне (AGPL-3.0, как у NPMplus).

Что остаётся принятым риском и почему кодом не закрывается:

- **root в контейнерах** (`DS-0002`, `CIS-DI-0001`, KICS Missing User): NPMplus стартует от root и сам переходит на
  `PUID`/`PGID`; агенту нужен сокет Docker для `nginxions-control` (System → Services), группа которого на каждом хосте
  своя. Без привилегий: `cap_drop: ALL`, `no-new-privileges`;
- **сокет Docker у `openappsec`** — для `nginxions-control` (белый список операций, токен, 127.0.0.1);
- **пакеты Alpine без исправления** (`busybox`/`ssl_client`, `coreutils`, `python3`/`sqlite-libs` для certbot в
  `nginxions`, `ada-libs`): записи с `"unfixed": true` перестают действовать, как только в Alpine появится версия с
  исправлением, — тогда находка снова открыта и обновляется пересборкой;
- **закреплённые версии apk** (KICS): Alpine хранит только текущую версию пакета, закрепление ломает сборку при каждом
  исправлении безопасности; базовые образы закреплены по digest;
- **настройки репозитория** (Scorecard: защита ветки, обязательный review, регистрация в OSS-Fuzz и OpenSSF Best
  Practices) — решает владелец репозитория.

В коде ложное срабатывание Semgrep помечается на строке выше: `// nosemgrep: <id правила> -- почему`.

## Локальный запуск

```bash
# отчёт по уже скачанным результатам (артефакты security-* прогона)
node scripts/security-report.mjs --in reports --out security-report --expect source,images,dast
# скан образов и DAST (нужны локальные образы, см. scripts/build-images.sh)
NGINXIONS_REGISTRY=local NGINXIONS_VERSION=dev scripts/scan-images.sh
NGINXIONS_REGISTRY=local NGINXIONS_VERSION=dev scripts/test-dast.sh
```

## Обновление сканеров

Версии и digest образов сканеров — в `.github/security/tools.env`, их поднимает Renovate. Новая версия сканера может
найти больше: проверьте отчёт перед слиянием.
