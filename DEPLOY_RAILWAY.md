# Быстрый запуск

### 1. GitHub
Залей все файлы этой папки в корень репозитория.

### 2. Railway
Подключи репозиторий как сервис.

### 3. PostgreSQL
В Railway добавь PostgreSQL. `DATABASE_URL` будет доступен сервису.

### 4. Volume
Создай Volume и подключи его к сервису с Mount Path:

`/data`

### 5. Variable
Создай:

`JWT_SECRET=<длинная случайная строка>`

### 6. Deploy
Start command уже задан в `railway.json`:

`node server.js`

Проверка:

`/api/health`

Ожидай `ok: true` и после подключения БД `database: true`.
