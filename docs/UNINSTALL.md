# Полное удаление NginxionS

Инструкция убирает с машины всё, что создаёт NginxionS:

- контейнеры;
- тома с данными: база, сертификаты, ключи CA, настройки, логи;
- сети;
- образы NginxionS и сторонние образы стека;
- кэш сборки;
- клон репозитория со всеми ветками;
- кэш интерфейса в браузере.

После этого установка начинается с нуля. Подходит для Linux и macOS. На Windows команды выполняются в WSL или Git Bash при запущенном Docker Desktop.

> **Удаление необратимо.** Пропадут хосты, сертификаты Let's Encrypt и их ключи, корневые CA и выданные клиентские сертификаты, пользователи, политика WAF, данные обучения агента, журнал событий. Если что-то из этого может понадобиться, сначала сделайте резервную копию (раздел 0).

## Почему «старое осталось» после переустановки

Обычно причина одна из двух:

1. **Остался старый образ.** Тег `develop` (или `latest`) уже лежит на машине, и `docker compose up` его не обновляет: стек запускается из старой сборки, даже если тома и папка удалены. Поэтому шаг 3 удаляет образы, а переустановка (раздел 7) скачивает их заново с `--pull always`.
2. **Браузер держит старый интерфейс.** Кэш и данные сайта панели переживают удаление сервера. Их чистит шаг 6.

Ещё одна частая ошибка — команды выполняются не в той папке. Клон может лежать где угодно (`~/nginxions`, `~/Документы/docker/nginxions`…), поэтому ниже путь задаётся переменной `NGINXIONS_DIR`.

## 0. Резервная копия (по желанию)

```bash
mkdir -p ~/nginxions-backup
for v in nginxions-data postgres-data secrets crowdsec-conf crowdsec-data appsec-localconfig appsec-data appsec-storage; do
  docker run --rm -v nginxions_$v:/v:ro -v ~/nginxions-backup:/b alpine tar czf /b/$v.tgz -C /v .
done
```

Самое ценное:

- `nginxions_postgres-data` — база: хосты, пользователи, PKI, события;
- `nginxions_nginxions-data` — сертификаты, конфиги nginx, ключи;
- `nginxions_secrets` — сгенерированные пароли и ключ шифрования ключей CA. Без него зашифрованные ключи из базы не расшифровать.

## Всё сразу

Шаги 1–5 одним блоком. Укажите в `NGINXIONS_DIR` свою папку с клоном. Если папки уже нет, блок всё равно удалит остатки по именам.

```bash
NGINXIONS_DIR=~/nginxions   # путь к клону, например ~/Документы/docker/nginxions

# 1. стек (прод, dev, тест закрытого контура) с томами и сетями
if [ -f "$NGINXIONS_DIR/deploy/compose.yaml" ]; then
  D="$NGINXIONS_DIR/deploy"
  docker compose -f "$D/compose.yaml" -f "$D/compose.dev.yaml" --profile attack down --volumes --remove-orphans
  docker compose -p nginxions-airgap -f "$D/compose.yaml" -f "$D/test/compose.airgap.yaml" --profile test \
    down --volumes --remove-orphans 2>/dev/null
fi
# свой compose.yaml вместо репозитория
if [ -f "$NGINXIONS_DIR/compose.yaml" ]; then
  docker compose -f "$NGINXIONS_DIR/compose.yaml" down --volumes --remove-orphans
fi

# 2. остатки по имени и метке
docker ps -aq --filter 'name=^nginxions' | xargs -r docker rm -f
docker ps -aq --filter 'label=nginxions.managed=true' | xargs -r docker rm -f
docker volume ls -q | grep -E '^nginxions' | xargs -r docker volume rm -f
docker network ls --format '{{.Name}}' | grep -E '^nginxions' | xargs -r docker network rm

# 3. образы NginxionS и сторонние образы стека, dev и тестов
docker images --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '(^|/)(nginxions(-openappsec|-appsec-[a-z-]+)?|crowdsecurity/crowdsec|tecnativa/docker-socket-proxy|postgres|traefik/whoami|curlimages/curl|zoeyvid/npmplus|node):' \
  | xargs -r docker rmi -f

# 4. кэш сборки и висячие слои
docker builder prune -af
docker image prune -f

# 5. клон (вместе с .git и всеми ветками) и резервная копия
rm -rf "$NGINXIONS_DIR" ~/nginxions-backup

# проверка: ничего не выводит
ls -d "$NGINXIONS_DIR" 2>/dev/null
docker ps -a | grep -i nginxions; docker volume ls | grep -i nginxions; docker network ls | grep -i nginxions
docker images | grep -iE 'nginxions|npmplus'
```

Если проверка что-то вывела, удалите это вручную (`docker rm -f`, `docker volume rm`, `docker rmi -f`) и повторите проверку.

Затем шаг 6 (браузер). Ниже — что делает каждый шаг и что учесть.

## 1. Стек

`docker compose … down --volumes --remove-orphans` останавливает контейнеры и удаляет тома и сети проекта `nginxions`.

- `-f deploy/compose.dev.yaml --profile attack` нужны, если запускался dev-стек: тогда удалятся `nginxions-test-upstream` и `nginxions-attacker`. На сервере, где был только прод-стек, лишними они не будут.
- Тест закрытого контура (`scripts/test-airgap.sh`) — отдельный проект `nginxions-airgap`.
- Если NginxionS запускался из своего `compose.yaml`, а не из репозитория, работает вторая команда.

## 2. Остатки

Compose удаляет только то, что знает по текущим файлам. Если файлы менялись или папки уже нет, остатки удаляются по имени и метке `nginxions.managed`.

| Что | Имена |
|---|---|
| Контейнеры | `nginxions`, `nginxions-openappsec`, `nginxions-postgres`, `nginxions-crowdsec`, `nginxions-nginxions-init-1`; от версий до ноября 2026: `nginxions-control`, `nginxions-socket-proxy`, `nginxions-appsec-agent`, `nginxions-appsec-shared-storage`, `nginxions-appsec-tuning-svc`; dev и тесты: `nginxions-test-upstream`, `nginxions-attacker`, `nginxions-airgap-*` |
| Тома | `nginxions_secrets`, `nginxions_nginxions-data`, `nginxions_postgres-data`, `nginxions_appsec-shm`, `nginxions_appsec-conf`, `nginxions_appsec-data`, `nginxions_appsec-logs`, `nginxions_appsec-localconfig`, `nginxions_appsec-model`, `nginxions_appsec-storage`, `nginxions_crowdsec-conf`, `nginxions_crowdsec-data`; тест: `nginxions-airgap_*` |
| Сети | `nginxions_edge`, `nginxions_internal` (и `nginxions_control` старых версий); тест: `nginxions-airgap_*` |

## 3. Образы

Без этого шага переустановка запустит старую сборку (см. начало).

- Образы NginxionS: `opensophy/nginxions`, `opensophy/nginxions-openappsec` (и `opensophy/nginxions-appsec-{agent,shared-storage,tuning}` старых версий) из Docker Hub, `local/nginxions*:dev` из `scripts/build-images.sh`, `nginxions:dev` из dev-стека.
- Сторонние: `crowdsecurity/crowdsec`, `postgres` (и `tecnativa/docker-socket-proxy` старых версий); для dev и тестов `traefik/whoami`, `curlimages/curl`, `zoeyvid/npmplus` (база dev-образа), `node` (сборка dev-образа). Если они нужны другим проектам на машине, уберите их из команды. Удалённый образ просто скачается заново при следующем запуске того проекта.

## 4. Кэш сборки

Если образы собирались на этой машине (`scripts/build-images.sh`, dev-стек), кэш BuildKit занимает гигабайты. `docker builder prune -af` чистит весь кэш сборки Docker, а не только NginxionS: следующая сборка других проектов пойдёт с нуля.

## 5. Папки

Клон удаляется целиком, вместе с `.git`: локальные ветки, история, `node_modules` фронтенда. Ветки на GitHub остаются.

Если не помните, где лежат клоны:

```bash
find ~ -maxdepth 5 -type d \( -iname 'nginxions*' -o -iname 'npmplus*' \) 2>/dev/null
```

Удалите найденное через `rm -rf`. Глобально ставился только `pnpm` (`npm i -g pnpm`). Если он не нужен: `npm rm -g pnpm`.

## 6. Браузер

Интерфейс панели кэшируется в браузере, а тема и язык хранятся в данных сайта. Откройте панель (`https://<сервер>:81`, для dev ещё `http://localhost:5173`) и очистите данные сайта:

- **Chrome, Edge, Chromium:** F12 → Application → Storage → «Clear site data»;
- **Firefox:** значок замка в адресной строке → «Удалить куки и данные сайта».

Потом обновите страницу с Ctrl+Shift+R. Можно проверить и в окне инкогнито.

Если после переустановки домен перекидывает на старый адрес, это кэшированный редирект браузера: см. [Решение проблем](TROUBLESHOOTING.md#браузер-перенаправляет-на-другой-адрес-хотя-редиректа-в-nginxions-нет).

Сертификаты, импортированные в браузер или ОС, удаляются отдельно: корневой CA NginxionS и клиентские `.p12` для mTLS. В Chrome на Linux это «Настройки → Конфиденциальность и безопасность → Безопасность → Управление сертификатами», в Firefox — «Настройки → Приватность и защита → Сертификаты», в Windows — `certmgr.msc`, в macOS — «Связка ключей».

## 7. Переустановка с нуля

```bash
git clone -b work https://github.com/opensophy-projects/NPMOS ~/nginxions
cd ~/nginxions
docker compose -f deploy/compose.yaml up -d --pull always
```

`--pull always` скачивает образы заново, даже если тег уже есть на машине. Проверка: `docker images | grep nginxions` показывает образы, созданные недавно, а не в день первой установки.

## 8. Что ещё проверить

- **Порты.** После удаления 80, 443 и 81 свободны: `ss -ltnp | grep -E ':(80|443|81)\b'` ничего не выводит.
- **Файрвол.** Если для NginxionS открывали порты (ufw, firewalld, security group в облаке), закройте их: `ufw delete allow 81/tcp` и т.п.
- **DNS.** Записи доменов, которые указывали на этот сервер, перенаправьте или удалите.
- **Docker Hub.** Если входили в Docker Hub только ради NginxionS: `docker logout`.
- **Docker целиком.** Если в Docker кроме NginxionS ничего нет, шаги 2–4 заменяет `docker system prune -af --volumes`. Эта команда удаляет **все** неиспользуемые контейнеры, образы, тома, сети и кэш Docker на машине.
