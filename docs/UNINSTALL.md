# Полное удаление NPMOS

Инструкция убирает с машины всё, что создаёт NPMOS:

- контейнеры;
- тома с данными (база, сертификаты, ключи CA, настройки, логи);
- сети;
- образы;
- кэш сборки;
- каталог с исходниками.

Подходит для сервера, ВМ и рабочего компьютера (Linux, macOS, Windows с Docker Desktop).

> **Удаление необратимо.** Пропадут хосты, сертификаты Let's Encrypt и их ключи, корневые CA и выданные клиентские сертификаты, пользователи, политика WAF, данные обучения агента, журнал событий. Если что-то из этого может понадобиться, сначала сделайте резервную копию (см. раздел 0).

Команды выполняются в каталоге с репозиторием NPMOS (там, где лежит `deploy/compose.yaml`). Если NPMOS запускался не из репозитория, а из своего `compose.yaml`, замените `-f deploy/compose.yaml` на путь к своему файлу. Проект Compose везде называется `npmos`.

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

## 1. Остановить и удалить контейнеры, тома и сети

```bash
docker compose -f deploy/compose.yaml -f deploy/compose.dev.yaml --profile attack down --volumes --remove-orphans
```

- `--volumes` удаляет все именованные тома проекта (`npmos_*`).
- `-f deploy/compose.dev.yaml --profile attack` нужны, если запускался dev-стек: тогда удалятся и `npmos-test-upstream`, и `npmos-attacker`. На сервере, где был только прод-стек, этот файл можно не указывать, лишним он не будет.

Если запускался тест закрытого контура (`scripts/test-airgap.sh`), у него отдельный проект:

```bash
docker compose -p npmos-airgap -f deploy/compose.yaml -f deploy/test/compose.airgap.yaml --profile test down --volumes --remove-orphans
```

## 2. Проверить, что ничего не осталось, и добить остатки

Compose удаляет только то, что знает по текущим файлам. Если файлы менялись или репозитория уже нет, удалите остатки по имени:

```bash
# контейнеры
docker ps -a --format '{{.Names}}' | grep -E '^npmos' | xargs -r docker rm -f

# тома
docker volume ls -q | grep -E '^npmos(-airgap)?_' | xargs -r docker volume rm

# сети
docker network ls --format '{{.Name}}' | grep -E '^npmos(-airgap)?_' | xargs -r docker network rm
```

Что должно исчезнуть:

| Что | Имена |
|---|---|
| Контейнеры | `npmos`, `npmos-control`, `npmos-postgres`, `npmos-crowdsec`, `npmos-socket-proxy`, `npmos-appsec-agent`, `npmos-appsec-smartsync`, `npmos-appsec-shared-storage`, `npmos-appsec-tuning-svc`, `npmos-npmos-init-1`; dev и тесты: `npmos-test-upstream`, `npmos-attacker`, `npmos-airgap-*` |
| Тома | `npmos_secrets`, `npmos_npmos-data`, `npmos_postgres-data`, `npmos_appsec-shm`, `npmos_appsec-conf`, `npmos_appsec-data`, `npmos_appsec-logs`, `npmos_appsec-localconfig`, `npmos_appsec-model`, `npmos_appsec-storage`, `npmos_crowdsec-conf`, `npmos_crowdsec-data`; тест: `npmos-airgap_*` (включая `test-state`) |
| Сети | `npmos_edge`, `npmos_internal`, `npmos_control`; тест: `npmos-airgap_*` |

Проверка — все три команды должны ничего не вывести:

```bash
docker ps -a | grep npmos
docker volume ls | grep npmos
docker network ls | grep npmos
```

## 3. Удалить образы

Образы NPMOS (из Docker Hub, собранные локально и dev):

```bash
docker images --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '(^|/)npmos(-appsec-(agent|smartsync|shared-storage|tuning))?:' \
  | xargs -r docker rmi -f
```

Удаляются:

- `opensophy/npmos*` из Docker Hub;
- `local/npmos*:dev` из `scripts/build-images.sh`;
- `npmos:dev` из dev-стека.

Сторонние образы, которые тянет стек. Удаляйте их, только если они не нужны другим проектам на этой машине:

```bash
docker rmi -f $(docker images -q crowdsecurity/crowdsec) \
              $(docker images -q tecnativa/docker-socket-proxy) \
              $(docker images -q 'postgres') 2>/dev/null
# dev и тесты:
docker rmi -f $(docker images -q traefik/whoami) $(docker images -q curlimages/curl) \
              $(docker images -q 'zoeyvid/npmplus') 2>/dev/null
```

`zoeyvid/npmplus` — база dev-образа. Он есть только там, где запускался `compose.dev.yaml`.

## 4. Кэш сборки

Если образы собирались на этой машине (`scripts/build-images.sh`, dev-стек), кэш BuildKit занимает гигабайты: сборка nginx и агента open-appsec.

```bash
docker builder prune -af
```

Команда очищает весь кэш сборки Docker, а не только кэш NPMOS. Обычно это безопасно: следующая сборка других проектов просто пойдёт с нуля.

Оставшиеся «висячие» слои:

```bash
docker image prune -f
```

## 5. Файлы на диске

```bash
# репозиторий (каталог, куда делали git clone)
rm -rf ~/npmos

# если делали резервную копию и она больше не нужна
rm -rf ~/npmos-backup
```

Каталог с исходниками для фронтенда (`npmos/frontend/node_modules`) удаляется вместе с репозиторием. Глобально ставился только `pnpm` (`npm i -g pnpm`). Если он не нужен:

```bash
npm rm -g pnpm
```

## 6. Что ещё проверить

- **Порты.** После удаления 80, 443 и 81 должны освободиться: `ss -ltnp | grep -E ':(80|443|81)\b'` (Linux) ничего не выводит.
- **Файрвол.** Если для NPMOS открывали порты (ufw, firewalld, security group в облаке), закройте их: `ufw delete allow 81/tcp` и т.п.
- **DNS.** Записи доменов, которые указывали на этот сервер, перенаправьте или удалите.
- **Docker Hub.** Если вы входили в Docker Hub только ради NPMOS: `docker logout`.
- **Сертификаты в браузерах и ОС.** Если в систему или браузер импортировали корневой CA NPMOS или клиентские сертификаты (.p12) для mTLS, удалите их там вручную. В Windows это `certmgr.msc`, в macOS — «Связка ключей», в Firefox — «Настройки → Сертификаты».
- **Docker целиком.** Если Docker ставился только ради NPMOS, его можно удалить средствами ОС. Тогда шаги 1–4 не нужны: удаление `/var/lib/docker` снимает всё сразу.

## Коротко: всё сразу, без резервной копии

Убирает только то, что относится к NPMOS, другие проекты в Docker не трогает. `NPMOS_DIR` — каталог, куда клонировали репозиторий. Если его уже нет, шаг с `docker compose` пропускается, остатки удаляются по именам.

```bash
NPMOS_DIR=~/npmos

# 1. стек (прод, dev, тест закрытого контура) вместе с томами и сетями
if [ -f "$NPMOS_DIR/deploy/compose.yaml" ]; then
  D="$NPMOS_DIR/deploy"
  docker compose -f "$D/compose.yaml" -f "$D/compose.dev.yaml" --profile attack down --volumes --remove-orphans
  docker compose -p npmos-airgap -f "$D/compose.yaml" -f "$D/test/compose.airgap.yaml" --profile test \
    down --volumes --remove-orphans 2>/dev/null
fi

# 2. остатки по имени и метке
docker ps -aq --filter 'name=^npmos' | xargs -r docker rm -f
docker ps -aq --filter 'label=npmos.managed=true' | xargs -r docker rm -f
docker volume ls -q | grep -E '^npmos(-airgap)?_' | xargs -r docker volume rm -f
docker network ls --format '{{.Name}}' | grep -E '^npmos(-airgap)?_' | xargs -r docker network rm

# 3. образы NPMOS
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '(^|/)npmos(-appsec-[a-z-]+)?:' | xargs -r docker rmi -f

# 4. сторонние образы стека, dev и тестов (пропустите, если они нужны другим проектам)
docker images --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '(^|/)(crowdsecurity/crowdsec|tecnativa/docker-socket-proxy|postgres|traefik/whoami|curlimages/curl|zoeyvid/npmplus|node):' \
  | xargs -r docker rmi -f

# 5. кэш сборки и висячие слои (весь кэш сборки Docker, не только NPMOS)
docker builder prune -af
docker image prune -f

# 6. файлы
rm -rf "$NPMOS_DIR" ~/npmos-backup

# проверка: все три команды ничего не выводят
docker ps -a | grep npmos; docker volume ls | grep npmos; docker network ls | grep npmos
```

Затем по разделу 6: порты, файрвол, DNS, импортированные в браузер или ОС CA и `.p12`.

Если кроме NPMOS в Docker ничего нет, шаги 2–5 можно заменить одной командой. Она удаляет **все** остановленные контейнеры, неиспользуемые образы, тома, сети и кэш Docker на машине:

```bash
docker system prune -af --volumes
```
