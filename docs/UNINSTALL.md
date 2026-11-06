# Полное удаление NPMOS

Инструкция убирает с машины всё, что создаёт NPMOS:

- контейнеры;
- тома с данными: база, сертификаты, ключи CA, настройки, логи;
- сети;
- образы NPMOS и сторонние образы стека;
- кэш сборки;
- клон репозитория со всеми ветками;
- кэш интерфейса в браузере.

После этого установка начинается с нуля. Подходит для Linux и macOS. На Windows команды выполняются в WSL или Git Bash при запущенном Docker Desktop.

> **Удаление необратимо.** Пропадут хосты, сертификаты Let's Encrypt и их ключи, корневые CA и выданные клиентские сертификаты, пользователи, политика WAF, данные обучения агента, журнал событий. Если что-то из этого может понадобиться, сначала сделайте резервную копию (раздел 0).

## Почему «старое осталось» после переустановки

Обычно причина одна из двух:

1. **Остался старый образ.** Тег `develop` (или `latest`) уже лежит на машине, и `docker compose up` его не обновляет: стек запускается из старой сборки, даже если тома и папка удалены. Поэтому шаг 3 удаляет образы, а переустановка (раздел 7) скачивает их заново с `--pull always`.
2. **Браузер держит старый интерфейс.** Кэш и данные сайта панели переживают удаление сервера. Их чистит шаг 6.

Ещё одна частая ошибка — команды выполняются не в той папке. Клон может лежать где угодно (`~/npmos`, `~/Документы/docker/npmos`…), поэтому ниже путь задаётся переменной `NPMOS_DIR`.

## 0. Резервная копия (по желанию)

```bash
mkdir -p ~/npmos-backup
for v in npmos-data postgres-data secrets crowdsec-conf crowdsec-data appsec-localconfig appsec-data appsec-storage; do
  docker run --rm -v npmos_$v:/v:ro -v ~/npmos-backup:/b alpine tar czf /b/$v.tgz -C /v .
done
```

Самое ценное:

- `npmos_postgres-data` — база: хосты, пользователи, PKI, события;
- `npmos_npmos-data` — сертификаты, конфиги nginx, ключи;
- `npmos_secrets` — сгенерированные пароли и ключ шифрования ключей CA. Без него зашифрованные ключи из базы не расшифровать.

## Всё сразу

Шаги 1–5 одним блоком. Укажите в `NPMOS_DIR` свою папку с клоном. Если папки уже нет, блок всё равно удалит остатки по именам.

```bash
NPMOS_DIR=~/npmos   # путь к клону, например ~/Документы/docker/npmos

# 1. стек (прод, dev, тест закрытого контура) с томами и сетями
if [ -f "$NPMOS_DIR/deploy/compose.yaml" ]; then
  D="$NPMOS_DIR/deploy"
  docker compose -f "$D/compose.yaml" -f "$D/compose.dev.yaml" --profile attack down --volumes --remove-orphans
  docker compose -p npmos-airgap -f "$D/compose.yaml" -f "$D/test/compose.airgap.yaml" --profile test \
    down --volumes --remove-orphans 2>/dev/null
fi
# свой compose.yaml вместо репозитория
if [ -f "$NPMOS_DIR/compose.yaml" ]; then
  docker compose -f "$NPMOS_DIR/compose.yaml" down --volumes --remove-orphans
fi

# 2. остатки по имени и метке
docker ps -aq --filter 'name=^npmos' | xargs -r docker rm -f
docker ps -aq --filter 'label=npmos.managed=true' | xargs -r docker rm -f
docker volume ls -q | grep -E '^npmos' | xargs -r docker volume rm -f
docker network ls --format '{{.Name}}' | grep -E '^npmos' | xargs -r docker network rm

# 3. образы NPMOS и сторонние образы стека, dev и тестов
docker images --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '(^|/)(npmos(-openappsec|-appsec-[a-z-]+)?|crowdsecurity/crowdsec|tecnativa/docker-socket-proxy|postgres|traefik/whoami|curlimages/curl|zoeyvid/npmplus|node):' \
  | xargs -r docker rmi -f

# 4. кэш сборки и висячие слои
docker builder prune -af
docker image prune -f

# 5. клон (вместе с .git и всеми ветками) и резервная копия
rm -rf "$NPMOS_DIR" ~/npmos-backup

# проверка: ничего не выводит
ls -d "$NPMOS_DIR" 2>/dev/null
docker ps -a | grep -i npmos; docker volume ls | grep -i npmos; docker network ls | grep -i npmos
docker images | grep -iE 'npmos|npmplus'
```

Если проверка что-то вывела, удалите это вручную (`docker rm -f`, `docker volume rm`, `docker rmi -f`) и повторите проверку.

Затем шаг 6 (браузер). Ниже — что делает каждый шаг и что учесть.

## 1. Стек

`docker compose … down --volumes --remove-orphans` останавливает контейнеры и удаляет тома и сети проекта `npmos`.

- `-f deploy/compose.dev.yaml --profile attack` нужны, если запускался dev-стек: тогда удалятся `npmos-test-upstream` и `npmos-attacker`. На сервере, где был только прод-стек, лишними они не будут.
- Тест закрытого контура (`scripts/test-airgap.sh`) — отдельный проект `npmos-airgap`.
- Если NPMOS запускался из своего `compose.yaml`, а не из репозитория, работает вторая команда.

## 2. Остатки

Compose удаляет только то, что знает по текущим файлам. Если файлы менялись или папки уже нет, остатки удаляются по имени и метке `npmos.managed`.

| Что | Имена |
|---|---|
| Контейнеры | `npmos`, `npmos-openappsec`, `npmos-postgres`, `npmos-crowdsec`, `npmos-npmos-init-1`; от версий до ноября 2026: `npmos-control`, `npmos-socket-proxy`, `npmos-appsec-agent`, `npmos-appsec-shared-storage`, `npmos-appsec-tuning-svc`; dev и тесты: `npmos-test-upstream`, `npmos-attacker`, `npmos-airgap-*` |
| Тома | `npmos_secrets`, `npmos_npmos-data`, `npmos_postgres-data`, `npmos_appsec-shm`, `npmos_appsec-conf`, `npmos_appsec-data`, `npmos_appsec-logs`, `npmos_appsec-localconfig`, `npmos_appsec-model`, `npmos_appsec-storage`, `npmos_crowdsec-conf`, `npmos_crowdsec-data`; тест: `npmos-airgap_*` |
| Сети | `npmos_edge`, `npmos_internal` (и `npmos_control` старых версий); тест: `npmos-airgap_*` |

## 3. Образы

Без этого шага переустановка запустит старую сборку (см. начало).

- Образы NPMOS: `opensophy/npmos`, `opensophy/npmos-openappsec` (и `opensophy/npmos-appsec-{agent,shared-storage,tuning}` старых версий) из Docker Hub, `local/npmos*:dev` из `scripts/build-images.sh`, `npmos:dev` из dev-стека.
- Сторонние: `crowdsecurity/crowdsec`, `postgres` (и `tecnativa/docker-socket-proxy` старых версий); для dev и тестов `traefik/whoami`, `curlimages/curl`, `zoeyvid/npmplus` (база dev-образа), `node` (сборка dev-образа). Если они нужны другим проектам на машине, уберите их из команды. Удалённый образ просто скачается заново при следующем запуске того проекта.

## 4. Кэш сборки

Если образы собирались на этой машине (`scripts/build-images.sh`, dev-стек), кэш BuildKit занимает гигабайты. `docker builder prune -af` чистит весь кэш сборки Docker, а не только NPMOS: следующая сборка других проектов пойдёт с нуля.

## 5. Папки

Клон удаляется целиком, вместе с `.git`: локальные ветки, история, `node_modules` фронтенда. Ветки на GitHub остаются.

Если не помните, где лежат клоны:

```bash
find ~ -maxdepth 5 -type d \( -iname 'npmos*' -o -iname 'npmplus*' \) 2>/dev/null
```

Удалите найденное через `rm -rf`. Глобально ставился только `pnpm` (`npm i -g pnpm`). Если он не нужен: `npm rm -g pnpm`.

## 6. Браузер

Интерфейс панели кэшируется в браузере, а тема и язык хранятся в данных сайта. Откройте панель (`https://<сервер>:81`, для dev ещё `http://localhost:5173`) и очистите данные сайта:

- **Chrome, Edge, Chromium:** F12 → Application → Storage → «Clear site data»;
- **Firefox:** значок замка в адресной строке → «Удалить куки и данные сайта».

Потом обновите страницу с Ctrl+Shift+R. Можно проверить и в окне инкогнито.

Если после переустановки домен перекидывает на старый адрес, это кэшированный редирект браузера: см. [Решение проблем](TROUBLESHOOTING.md#браузер-перенаправляет-на-другой-адрес-хотя-редиректа-в-npmos-нет).

Сертификаты, импортированные в браузер или ОС, удаляются отдельно: корневой CA NPMOS и клиентские `.p12` для mTLS. В Chrome на Linux это «Настройки → Конфиденциальность и безопасность → Безопасность → Управление сертификатами», в Firefox — «Настройки → Приватность и защита → Сертификаты», в Windows — `certmgr.msc`, в macOS — «Связка ключей».

## 7. Переустановка с нуля

```bash
git clone -b work https://github.com/opensophy-projects/npmos ~/npmos
cd ~/npmos
docker compose -f deploy/compose.yaml up -d --pull always
```

`--pull always` скачивает образы заново, даже если тег уже есть на машине. Проверка: `docker images | grep npmos` показывает образы, созданные недавно, а не в день первой установки.

## 8. Что ещё проверить

- **Порты.** После удаления 80, 443 и 81 свободны: `ss -ltnp | grep -E ':(80|443|81)\b'` ничего не выводит.
- **Файрвол.** Если для NPMOS открывали порты (ufw, firewalld, security group в облаке), закройте их: `ufw delete allow 81/tcp` и т.п.
- **DNS.** Записи доменов, которые указывали на этот сервер, перенаправьте или удалите.
- **Docker Hub.** Если входили в Docker Hub только ради NPMOS: `docker logout`.
- **Docker целиком.** Если в Docker кроме NPMOS ничего нет, шаги 2–4 заменяет `docker system prune -af --volumes`. Эта команда удаляет **все** неиспользуемые контейнеры, образы, тома, сети и кэш Docker на машине.
