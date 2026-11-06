# npmos/

Основа NPMOS: [NPMplus](https://github.com/ZoeyVid/NPMplus) (git subtree, только релизные теги) с изменениями NPMOS.

- Код NPMOS — в `backend/npmos/` и `frontend/src/npmos/`; изменения файлов NPMplus помечены `NPMOS:`.
- Образ `npmos` собирается из `Dockerfile` этого каталога (CI); быстрый dev-образ — `deploy/dev/Dockerfile`.
- Файлы NPMplus, которые NPMOS не использует, удалены (список — в `CLAUDE.md`, «Удалено из upstream»).

Запуск, документация и архитектура — в корне репозитория: `README.md`, `CODE_OF_CONDUCT.md`, `CLAUDE.md`.
