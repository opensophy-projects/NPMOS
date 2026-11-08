# nginxions/

Основа NginxionS: [NPMplus](https://github.com/ZoeyVid/NPMplus) (git subtree, только релизные теги) с изменениями NginxionS.

- Код NginxionS — в `backend/nginxions/` и `frontend/src/nginxions/`; изменения файлов NPMplus помечены `NginxionS:`.
- Образ `nginxions` собирается из `Dockerfile` этого каталога (CI); быстрый dev-образ — `deploy/dev/Dockerfile`.
- Файлы NPMplus, которые NginxionS не использует, удалены (список — в `CLAUDE.md`, «Удалено из upstream»).

Запуск, документация и архитектура — в корне репозитория: `README.md`, `CODE_OF_CONDUCT.md`, `CLAUDE.md`.
