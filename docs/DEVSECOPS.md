# DevSecOps: проверки безопасности в CI

Все проверки идут внутри GitHub Actions. Ни один инструмент не требует аккаунта на другом сайте: каждый запускается
в задаче из образа, закреплённого по версии и digest (`.github/security/tools.env`). Результаты остаются в GitHub.

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
| Качество | **jscpd**, покрытие тестами | дублирование кода, покрытие backend (`node --test`) и frontend (vitest) | `security.yml` |

Код агента NginxionS (`openappsec/`: агент, attachment, shared storage, tuning, smartsync) проверяется теми же
сканерами, что и остальной код: Semgrep, CodeQL (C/C++, Go), Gitleaks, OSV-Scanner, hadolint, Trivy config, KICS. Его
находки пока показываются в отчёте и не блокируют, как и находки upstream NPMplus: это код open-appsec, который мы
разбираем и исправляем.

К ним добавляются проверки, которые были и раньше: biome, tsc, тесты, shellcheck, `compose config`, закрытый контур.

DAST (`scripts/test-dast.sh`) поднимает прод-стек, настраивает его как администратор в GUI (`deploy/test/dast-setup.sh`:
первый админ, корневой CA и серверный сертификат PKI NginxionS, прокси-хост `dast.local` с TLS, HTTP/2, HSTS и фильтром
эксплойтов) и атакует его из контейнеров той же сети. У каждого сканера свой адрес, поэтому бан CrowdSec одного сканера
не останавливает другие. Сканеры идут параллельно.

## Когда запускается

| Глубина | Что входит | Когда |
|---|---|---|
| **Быстрая** (~5–10 мин) | lint, типы, тесты, `security.yml`: Semgrep, CodeQL, Gitleaks, OSV-Scanner, SBOM исходников, IaC, workflow, качество | каждый push в любую ветку |
| **Полная** (~45 мин) | быстрая + сборка образов, закрытый контур, скан образов, DAST, шлюз перед публикацией | push в `work`, теги `v*`, pull request, кнопка Run workflow, ветки `security/**`, push с `[full]` в сообщении коммита |

**Каждую неделю** (понедельник, `security-weekly.yml`): от `work` создаётся ветка `security/<дата>` и на ней
запускается полный CI, плюс скан образов, уже опубликованных на Docker Hub (новые CVE в выпущенных версиях). По
итогам открывается issue «✅/❌ Отчёт безопасности <дата>» с меткой `security`: приходит уведомление, видна
история по неделям. Ветки старше 8 недель удаляются. Запустить вне расписания: Actions → Weekly security → Run
workflow. Проверить свою ветку полностью: назовите её `security/…` или добавьте `[full]` в сообщение коммита.

Ветку, созданную токеном workflow, GitHub не запускает (защита от цепочек), поэтому `security-weekly.yml` сам
запускает CI на новой ветке.

## Что блокирует

Политика — одна, в начале `scripts/security-report.mjs`:

| Проверка | Блокирует |
|---|---|
| Semgrep, CodeQL | высокие и критические находки **в коде NginxionS** (`nginxions/backend/nginxions`, `nginxions/frontend/src/nginxions`, `deploy`, `scripts`, `.github`); в коде upstream NPMplus — только в отчёт |
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
  проверок (сколько критических, высоких, средних и низких находок, что блокирует), блокирующие находки, принятые
  риски, SBOM, метрики качества и подробности по каждому инструменту.
- **Артефакт `security-report`** (внизу страницы прогона):
  - `security-report.html` — тот же отчёт страницей со всеми находками;
  - `security-report.md` — он же в Markdown;
  - `sbom/` — SBOM каждого состава: `source-backend`, `source-frontend`, `nginxions`, `nginxions-openappsec`;
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

## Принятые риски

Если находку нельзя или не нужно исправлять (нет исправления upstream, ложное срабатывание), её вносят в
`.github/security/accepted-risks.json`:

```json
{
	"risks": [
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

`tool` — id проверки из `scripts/security-report.mjs` (`semgrep`, `codeql-js`, `gitleaks`, `osv`, `trivy-nginxions`, `zap-api`…)
или `*`; `where` — часть места находки (необязательно). После даты `until` находка снова блокирует, и решение
нужно принять заново. Принятые риски показываются в отчёте отдельным разделом.

Во вкладку **Security → Code scanning** GitHub они не попадают: перед загрузкой SARIF `scripts/sarif-accepted.mjs`
убирает из него принятые риски этого инструмента и находки, подавленные в коде (`// nosemgrep: <правило> -- почему`);
GitHub закрывает такие оповещения при следующем анализе. Сам GitHub читает подавления только у CodeQL, поэтому без
этого шага каждое принятое и подавленное оставалось бы открытым оповещением. Полные результаты остаются в артефактах
и в отчёте.

Открытые задачи, которые ложными срабатываниями не являются и решаются отдельной работой:

- **контейнер `nginxions` работает от root** (`PUID=0`, как в NPMplus по умолчанию), хотя без привилегий: `cap_drop: ALL`,
  только `NET_BIND_SERVICE` и `SETGID`, `no-new-privileges`. Для запуска от другого пользователя стартовый скрипт
  NPMplus должен уметь обойтись без `CHOWN`/`SETUID`;
- **возможности остальных контейнеров** (`openappsec`, `postgres`, `crowdsec`) не урезаны: нужный каждому набор ещё
  не измерен; у всех `no-new-privileges`;
- **настройки репозитория** (Scorecard): защита ветки `work`, обязательный review, лицензия — решает владелец.

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
