# NetVault - Памятка для Claude

## При изменении кода ВСЕГДА:

### 1. Git репозиторий
```bash
git add .
git commit -m "описание изменений"
git push -u https://loltt89:TOKEN@github.com/loltt89/netvault-react.git main
```
- Репозиторий: https://github.com/loltt89/netvault-react
- Владелец: loltt89 (khamidt89@gmail.com)

### 2. Архив установки
```bash
cd /home/loltt && rm -f netvault-installer.tar.gz && \
tar --exclude='netvault-react/backend/venv' \
    --exclude='netvault-react/frontend/node_modules' \
    --exclude='netvault-react/frontend/build' \
    --exclude='netvault-react/backend/__pycache__' \
    --exclude='netvault-react/backend/*/__pycache__' \
    --exclude='netvault-react/backend/.env' \
    --exclude='netvault-react/frontend/.env' \
    --exclude='netvault-react/.git' \
    --exclude='netvault-react/.claude' \
    --exclude='netvault-react/backend/celerybeat-schedule' \
    -czf netvault-installer.tar.gz netvault-react && \
md5sum netvault-installer.tar.gz > netvault-installer.tar.gz.md5
```
- Архив: `/home/loltt/netvault-installer.tar.gz`

## Структура проекта
- Backend: Django + DRF + Celery (`/home/loltt/netvault-react/backend/`)
- Frontend: React + TypeScript (`/home/loltt/netvault-react/frontend/`)
- Установщик: `install.sh` (интерактивный)

## Тестовый сервер
- IP: 192.168.100.137
- User: kokadmin
- Pass: Zxcv12!@

## Важно
- .env файлы НЕ коммитить (есть в .gitignore)
- Frontend API URL: относительный `/api/v1` (не localhost!)
- Redis защищён паролем (генерируется при установке)
