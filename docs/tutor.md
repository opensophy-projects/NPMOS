![](https://habrastorage.org/webt/82/cf/28/82cf28e8228e925ac1338acd9cbf51c7.png)

Ох уж этот «ИИ-пентест» (AI Pentest) — за последнее время я очень много о нём наслышан, чуть ли не из каждого утюга (и из моих собственных рекомендаций в том числе). А как же защита? Кто будет защищать сервисы, пока все обсуждают атаку? Сегодня поговорим про open-appsec, поделюсь с вами опытом использования, покажу, как его настроить, а в конце статьи будут полезные «бонусы» и одна небольшая просьба к читателям. Проект подойдёт, если у вас есть homelab или небольшой/средний продакшн и вы хотите закрыть веб-сервисы адекватным WAF без раздутого стека и без обязательной привязки к облаку. Моя личная оценка после нескольких месяцев использования: open-appsec — достаточно «умный» щит для небольшой homelab, с парой шероховатостей, о которых я расскажу отдельно.

# Что такое OpenAppSec?

open-appsec — это межсетевой экран веб-приложений (WAF, Web Application Firewall) с открытым исходным кодом, который использует машинное обучение для автоматической защиты веб-сервисов и API. Проект изначально развивался при поддержке компании Check Point. Что значит «изначально»? Это означает лишь то, что Check Point создала проект и вывела его на рынок. Сейчас он медленно развивается (именно open-source) и разделён на 2 типа: для сообщества (open-appsec) и их коммерческая версия (Check Point WAF).

Статьи, которые я читал на эту тему, были в основном ориентированы на зависимость от их SaaS / Облако. В этой статье мы сделаем всё полностью локально стеком nginx proxy manager + openappsec + juiceshop (для теста).

## Какие возможны интеграции?

![На текущий момент доступны следующие интеграции](https://habrastorage.org/webt/88/00/bc/8800bcf80a96307e471f5328202ddc4b.png)

Вот не хватает, в идеале, ещё интеграции с Traefik, но кое-кто из энтузиастов homelab-еров смог настроить связку через CrowdSec, внутри которой уже был Traefik. [Ссылка] на то, как это реализовали(https://forum.samohosting.ru/t/polnoe-rukovodstvo-traefik-crowdsec-s-appsec-waf-v-lxc-kontejnere-na-proxmox-i-vishenka-na-torte/1991).

## Сколько нужно ресурсов?

Тут всё зависит от количества и «тяжести» ваших веб-ресурсов. В моём случае — homelab на 10 сервисов, где open-appsec занял примерно 1 ГБ оперативной памяти (на пике до ~3 ГБ) и около 8 из 20 ГБ выделенного места на диске. Согласно документации и разделу вопросов-ответов (Q&A, Questions & Answers) проекта, в среднем один поток процессора (1 vCPU-ядро) способен обрабатывать около 500 запросов в секунду (RPS, Requests Per Second). При активной атаке или DDoS нагрузка, думаю, будет заметно выше, поскольку open-appsec использует алгоритмы машинного обучения для контекстного анализа каждого запроса — а значит, он более требователен к процессору, чем классические WAF на регулярных выражениях. В моменты пиковой нагрузки или при анализе «тяжёлого» контента (например, страниц с обилием картинок и вложенных запросов) загрузка выделенных ядер процессора может кратковременно доходить до 100%. Проверим это на практике в следующей части статьи, когда я попробую атаковать свой сервер небольшим DDoS, а также XSS, RCE, SQLi и другими типами атак.

Но в целом homelab — это отличный WAF, который мне понравился. Не всё в нём идеально, ниже разберём и проблемы. Я выбрал именно его в первую очередь из-за скромного потребления ресурсов сервера и достаточной «сообразительности»: по большей части не приходится заниматься тонкой настройкой.

## Что вообще за агент у open-appsec? Это LLM?

Нет, это не большая языковая модель (LLM, Large Language Model). **Если говорить простым языком**, open-appsec — это фоновый процесс-охранник, который сидит рядом с прокси-сервером и на каждый входящий HTTP-запрос смотрит: похоже это на атаку (SQL-инъекция, удалённое выполнение кода (RCE, Remote Code Execution) и тому подобное) или нет. Агент сверяет запрос с готовым набором сигнатур атак, и если что-то выглядит подозрительно — дополнительно проверяет его по локальной статистике поведения именно вашего сайта и на основе этого решает, пропустить запрос или заблокировать его. По словам разработчиков, агент успешно блокировал уязвимости нулевого дня (zero-day). **С технической точки зрения** в агенте работают две модели: контролируемая (Supervised), заранее обученная на миллионах запросов и сравнивающая признаки входящего запроса с известными паттернами атак, и неконтролируемая (Unsupervised), которая подключается, только если запрос показался подозрительным, и оценивает его на основе локально накопленного поведения именно вашего сайта, выдавая финальную оценку (score). Это «базовая» модель. Есть и улучшенная версия, которую нужно получать через портал проекта, но этим мы заниматься не будем — рассмотрим только базовую.

> Могу ошибиться, но в терминологии это вроде классифицируется как классические дискриминативные модели машинного обучения. В общем, классификатор.

## Синтаксис конфигурации

В проекте на данный момент существуют версии синтаксиса: v1beta2 (в статусе беты) и v1beta1, которую мы и будем использовать на практике, поскольку у неё есть нормальная интеграция с nginx proxy manager. Для подробного изучения синтаксиса оставлю ссылку на [документацию проекта](https://docs.openappsec.io/getting-started/start-with-docker/local-policy-file-advanced).

# Развёртывание стека для обучения

Будем ставить связку из nginx proxy manager + open-appsec + juice-shop, поскольку это довольно простой «продакшн»-уровень (да и nginx многие используют — сам я себе чуть позже настрою что-то похожее на Traefik либо разберу совместную работу с ним отдельно) и заодно наглядно увидим работу WAF в деле.

> **Что это и зачем:** коротко поясню, что такое каждый компонент стека, прежде чем переходить к установке.

**Nginx Proxy Manager (NPM)** — это веб-панель поверх nginx, которая позволяет настраивать обратный прокси-сервер (reverse proxy), выпускать сертификаты и управлять доменами без ручного редактирования конфигурационных файлов nginx.

**open-appsec** — тот самый WAF с машинным обучением, о котором мы говорим в статье; в нашем случае он подключается как отдельный компонент (attachment) к NPM и анализирует трафик, проходящий через прокси.

**OWASP Juice Shop** — намеренно уязвимое веб-приложение (сайт-магазин), созданное специально для тренировки навыков тестирования на проникновение (пентеста) и демонстрации типичных веб-уязвимостей: SQL-инъекций, межсайтового скриптинга (XSS, Cross-Site Scripting) и других. Мы используем его как «жертву» для проверки работы WAF.

## Установка

![](https://habrastorage.org/webt/9e/01/0b/9e010bc48931f954c65e44b65199b79b.png)

### Подготовка

Здесь я бы очень советовал делать всё пошагово, если вы не сильны в администрировании Linux и не хотите долго заниматься поиском и устранением неисправностей (траблшутингом) — иначе стек может не заработать. Желательно выполнять установку без `sudo` и других повышенных привилегий: можно случайно сломать установку, и агент перестанет писать логи (чаще всего из-за разницы в правах на файлы). Я ставил так от обычного владельца юзера на своей homelab: 

Выберите, где будет у вас храниться это всё дело:

### Создать docker-compose.yaml

```bash
services:  
  appsec-npm:  
    container_name: npm-attachment  
    image: 'ghcr.io/openappsec/nginx-proxy-manager-attachment:latest'  
    ipc: host  
    restart: unless-stopped  
    ports:  
      - '80:80'  
      - '443:443'  
      - '81:81'  
    volumes:  
      - ./data:/data  
      - ./letsencrypt:/etc/letsencrypt  
      - ./appsec-logs:/ext/appsec-logs  
      - ./appsec-localconfig:/ext/appsec  
  
  appsec-agent:  
    container_name: appsec-agent  
    image: 'ghcr.io/openappsec/agent:latest'  
    network_mode: service:appsec-npm  
    ipc: host  
    restart: unless-stopped  
    environment:  
      - user_email=user@email.com  
      - nginxproxymanager=true  
      - autoPolicyLoad=true  
    volumes:  
      - ./appsec-config:/etc/cp/conf  
      - ./appsec-data:/etc/cp/data  
      - ./appsec-logs:/var/log/nano_agent  
      - ./appsec-localconfig:/ext/appsec  
    command: /cp-nano-agent --standalone  
  
  appsec-smartsync:  
    profiles:  
      - standalone  
    image: ghcr.io/openappsec/smartsync:latest  
    container_name: appsec-smartsync  
    environment:  
      - SHARED_STORAGE_HOST=appsec-shared-storage  
    restart: unless-stopped  
    depends_on:  
      - appsec-shared-storage  
  
  appsec-shared-storage:  
    profiles:  
      - standalone  
    image: ghcr.io/openappsec/smartsync-shared-files:latest  
    container_name: appsec-shared-storage  
    ipc: host  
    restart: unless-stopped  
    user: root  
    volumes:  
      - ./appsec-smartsync-storage:/db:z  
  
  appsec-tuning-svc:  
    profiles:  
      - standalone  
    image: ghcr.io/openappsec/smartsync-tuning:latest  
    container_name: appsec-tuning-svc  
    environment:  
      - SHARED_STORAGE_HOST=appsec-shared-storage  
      - QUERY_DB_PASSWORD=pass  
      - QUERY_DB_HOST=appsec-db  
      - QUERY_DB_USER=postgres  
    restart: unless-stopped  
    volumes:  
      - ./appsec-config:/etc/cp/conf  
    depends_on:  
      - appsec-shared-storage  
      - appsec-db  
  
  appsec-db:  
    profiles:  
      - standalone  
    image: postgres:18  
    container_name: appsec-db  
    restart: unless-stopped  
    environment:  
      - POSTGRES_PASSWORD=pass  
      - POSTGRES_USER=postgres  
    volumes:  
      - ./appsec-postgres-data:/var/lib/postgresql  
  
  juiceshop-backend:  
    image: bkimminich/juice-shop:latest  
    container_name: juiceshop-backend  
    profiles:  
      - juiceshop
```

``.env`` тоже:

```bash
COMPOSE_PROFILES=standalone,juiceshop  
```

### Скачать local_policy.yaml (в ./appsec-localconfig/)

```bash
mkdir -p ./appsec-localconfig  
wget https://raw.githubusercontent.com/openappsec/open-appsec-npm/main/deployment/local_policy.yaml -O ./appsec-localconfig/local_policy.yaml
```

> Если наблюдаются проблемы с подключением, содержимое политики вставьте в local_policy.yaml

```bash
policies:
  default:
    triggers:
    - appsec-default-log-trigger
    mode: inactive
    practices:
    - webapp-default-practice
    custom-response: appsec-default-web-user-response
  specific-rules: []

practices:
  - name: webapp-default-practice
    web-attacks:
      max-body-size-kb: 1000000
      max-header-size-bytes: 102400
      max-object-depth: 40
      max-url-size-bytes: 32768
      minimum-confidence: high
      override-mode: inactive
      protections:
        csrf-protection: inactive
        error-disclosure: inactive
        non-valid-http-methods: false
        open-redirect: inactive
    anti-bot:
      injected-URIs: []
      validated-URIs: []
      override-mode: inactive
    snort-signatures:
      configmap: []
      override-mode: inactive
    openapi-schema-validation:
      configmap: []
      override-mode: inactive

log-triggers:
  - name: appsec-default-log-trigger
    access-control-logging:
      allow-events: false
      drop-events: true
    additional-suspicious-events-logging:
      enabled: true
      minimum-severity: high
      response-body: false
      response-code: true
    appsec-logging:
      all-web-requests: false
      detect-events: true
      prevent-events: true
    extended-logging:
      http-headers: false
      request-body: false
      url-path: true
      url-query: true
    log-destination:
      cloud: false
      stdout:
        format: json

custom-responses:
  - name: appsec-default-web-user-response
    mode: response-code-only
    http-response-code: 403
```

**Делаем в таком порядке, потом запускаем**

```bash
mkdir -p ./appsec-config ./appsec-data ./appsec-logs ./appsec-smartsync-storage ./appsec-postgres-data ./data ./letsencrypt  
docker compose up -d  
docker compose ps
```

После запуска заходим на ``http://<IP-вашего-сервера>:81``, логин ``admin@example.com``, пароль ``changeme`` — сразу попросит их сменить.

![](https://habrastorage.org/webt/85/d0/87/85d08706d8f301c2d388ec1a3193da89.png)

![](https://habrastorage.org/webt/4e/2a/2e/4e2a2ed5ccdeac1121dcafcd205cb6ff.png)

Как уже заметили, те, кто пользуется NPM и знаком с интерфейсом, — появился новый раздел Security Log.

![Раздел All Events — логи работы агента](https://habrastorage.org/webt/73/03/ad/7303adfeade0224aa02478a687c5c360.png)

![Раздел Important Events — сюда будет приходить информация о действиях агента (например, о том, что он заблокировал SQL-инъекцию)](https://habrastorage.org/webt/70/24/1d/70241d2e6063e0a9ba0b1d56fdd487eb.png)

Сейчас там пусто, поскольку у нас ещё нет сервиса, который находится под защитой прокси. Добавим наш juice-shop: **Hosts/Proxy Hosts/Add Proxy Host**.

![](https://habrastorage.org/webt/cd/82/13/cd8213c214c855cba075f0ce21fc5e65.png)

![](https://habrastorage.org/webt/06/6b/d7/066bd7c663b0654f01a4112cd64ae00b.png)

Настраиваем сервис: выдаём ему HTTPS, привязываем субдомен и обязательно включаем open-appsec **в режиме принудительного контроля (Enforcement Mode) — Detect-Learn**. Это режим, при котором модель только обучается на трафике и ничего не блокирует, — так мы даём ей время «понять», какой трафик для нашего сайта нормален, и заодно проверим, правильно ли она распознаёт типичные атаки. Параметр Minimum confidence for prevent (минимальный уровень уверенности для блокировки) оставляем на значении High.

### Проверяем, на что оно способно

![еее лютые хакеры](https://habrastorage.org/webt/2f/b7/f7/2fb7f7acd144e535d65ad1dd3cc61c7e.gif)

Вообще, как только ваш сервис выйдет в интернет, у вас сразу агент будет ругаться на ботов, которые сканируют ваш сервис) Это нормально. Давайте зайдём теперь на Juice Shop и в качестве примера для статьи сделаем простейшую SQL-инъекцию (SQLi), чтобы показать, как всё это работает.

#### Атака в формате SQLi / Detect-Learn

![Находим поле регистрации и пробуем захватить админа](https://habrastorage.org/webt/3f/82/25/3f82258368230dc2b12ba0600c9c141f.png)

![И у нас получилось.](https://habrastorage.org/webt/ee/16/ac/ee16ac9d7e81eb423f2009cea68f4e90.png)

Смотрим теперь в Important Events

![](https://habrastorage.org/webt/ed/48/7f/ed487fe0fef20cc1efdea9c65938a14f.png)

Здесь интересны IP-адреса (которые я, разумеется, не покажу :) ), тип атаки (как её классифицировала модель) и данные о действиях атакующего в отдельной, выделенной красным зоне. Зачем нам всё это интересно? На практике — чтобы понимать, откуда идёт атака (для последующей блокировки по географии или конкретному адресу через списки исключений) и насколько «умной» была атака: по типу и содержимому запроса видно, было ли это ручное вмешательство человека или автоматическое сканирование ботом. Это помогает решить, стоит ли усиливать защиту конкретно для этого пути или достаточно текущих настроек.

Итак, мы убедились, что WAF работает и корректно фиксирует атаку. Мы также немного полазили по сайту сами (ну типа пару минут потыкать, походить по страницам), тем самым погоняв легальный трафик обычного пользователя, — модель успела на нём поучиться. Теперь возвращаемся в Hosts и меняем режим на **Prevent-Learn**.

![Prevent-Learn be like](https://habrastorage.org/webt/ba/89/3d/ba893dcff2ab196ad94498442f2edf17.gif)

#### Атака в формате SQLi / Detect-Learn

Повторяем атаку и получаем блокировку:

![](https://habrastorage.org/webt/14/c3/98/14c39868a31fcf281f5660ba030a7f23.png)

В XSS / RCE, если будем атаковать, то получим белый экран (блокировку запроса). Ну и, соответственно, если открыть «тело» в логах, можем в этом убедиться:

![](https://habrastorage.org/webt/4f/b6/1d/4fb61dc6c75d183584b1c3e8482614ac.jpg)

# На этом всё?

> **Что это и зачем:** разберём проблемы, с которыми реально можно столкнуться при эксплуатации open-appsec, и как их решать через исключения.

Не совсем. В процессе работы и настройки возникали свои сложности. Одну из них мы уже обсудили выше — это установка, где действительно стоит быть аккуратным и идти по пунктам. Следующая проблема, с которой стоит разобраться, — ложные блокировки. Допустим, модель заблокировала (или продолжает блокировать) именно ваш легальный трафик.

## Как сберечь легальный трафик, если его блокируют?

Такое случается довольно редко, обычно из-за неправильной настройки конфигурации. Для этого в open-appsec есть механизм исключений (exceptions) в файле `local_policy.yaml` — он позволяет сказать: «этот путь или источник — легитимный, не нужно его блокировать». Например:

```bash 
# Пример 1 — разрешение по стране
exceptions:  
  - name: exception-example  
    action: "accept"  
    condition:  
      - key: "countryCode"  
        value: "US"
#  Пример 2 — разрешение по IP
exceptions:  
  - name: exception-example-ip  
    action: "accept"  
    condition:  
      - key: "sourceIp"  
        value: "пишите тут IP""
```

Здесь мы разрешили весь трафик из США, минуя проверку WAF. То же самое можно сделать и с путями, IP-адресами и другими условиями. Опять же, стоит самостоятельно свериться с актуальным синтаксисом под ваш стек в документации проекта. **Есть также CLI-тюнинг (настройка через интерфейс командной строки)**, который работает внутри контейнера агента независимо от того, что стоит перед ним — NGINX, NPM, Kong и так далее. Насколько я знаю, эта функциональность **пока в состоянии беты**, и мне не удалось нормально её протестировать — не из-за проблем как таковых, а просто потому, что у меня не возникало реального случая для её использования: агент и без тонкой настройки работает штатно, а искусственно сымитировать необходимость в CLI-тюнинге у меня не вышло. Так что оставляю эту тему на самостоятельное изучение всем желающим.

## Заключение

Итак)

Мы разобрали интересный и по-своему классный проект — open-appsec: как его развернуть локально без привязки к облаку, как проверить на типовых атаках вроде SQL-инъекций, XSS и RCE и как настраивать исключения для легального трафика. На мой взгляд, для homelab и небольших продакшн-сценариев это один из немногих WAF, которые дают приличный уровень защиты почти без затрат времени на постоянную донастройку и потребление оперативы и других ресурсов — и в этом, по моему мнению, преимущество перед классическими решениями.

Теперь — та самая просьба. В Opensophy планируется сделать форк проекта open-appsec совместно с NPM, создав свой аналог облачного решения: добавить туда более простое и удобное управление WAF и аналитику, чтобы в итоге получился достойный набор «прокси + WAF», доступный для всех желающих. Если у вас есть желание присоединиться к разработке такого форка — напишите мне в личные сообщения на Хабре или в [Телеграме](https://t.me/opensophy). Обсудим, что вместе сможем сделать.

**Полезные ссылки**

- [Github-монорепозиторий open-appsec от Opensophy](https://github.com/opensophy-projects/oasm)

- [Задать вопросы ИИ по проекту на основе монорепозитория](https://deepwiki.com/opensophy-projects/oasm)

- [Официальная документация open-appsec](https://docs.openappsec.io/)

 © 2026 ООО «МТ ФИНАНС»
