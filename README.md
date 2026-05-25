# ECONO Engine API — DevSecOps Security Assessment

**Стек:** Python / FastAPI / Docker / Nginx / GitHub Actions / Semgrep / Trivy / Gitleaks / OWASP ZAP

---

## Что сделано

| Шаг | Описание | Статус |
|-----|----------|--------|
| 1. SAST (Semgrep) | Статический анализ кода, исправлены Critical/High | ✅ |
| 2. Dependency Scan (Trivy) | Сканирование зависимостей и Docker-образа | ✅ |
| 3. Управление секретами | Убраны hardcoded secrets, настроен .env + gitleaks | ✅ |
| 4. CI/CD pipeline | GitHub Actions с security gates | ✅ |
| 5. Server Hardening | Ubuntu 22.04, UFW, fail2ban, SSH, Nginx headers | ✅ |
| 6. DAST (OWASP ZAP) | Динамическое тестирование задеплоенного приложения | ✅ |

---

## Структура репозитория

```
.
├── app/
│   ├── main.py              # FastAPI-приложение (исправленная версия)
│   └── utils.py             # Утилиты: hashing, validation, logging
├── nginx/
│   └── nginx.conf           # Конфигурация с security headers
├── .github/
│   └── workflows/
│       └── security.yml     # CI/CD security pipeline
├── .env.example             # Шаблон переменных окружения
├── .gitignore               # .env исключён из истории
├── config.yaml              # Конфигурация через env-ссылки (без паролей)
├── docker-compose.yml
├── Dockerfile               # non-root пользователь
└── requirements.txt         # Обновлённые зависимости
```

---

## Быстрый старт

### Локальный запуск

```bash
# 1. Скопировать шаблон окружения и заполнить значения
cp .env.example .env

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить приложение
uvicorn app.main:app --reload
```

API доступен по адресу: `http://localhost:8000`

### Docker Compose

```bash
docker-compose up --build
```

---

## Как проверить каждый пункт

### Шаг 1 — SAST (Semgrep)

```bash
# Установить Semgrep
pip install semgrep

# Запустить сканирование
semgrep --config auto ./app
```

**Что было найдено и исправлено:**

**Сгруппированный список основных находок Semgrep (до исправлений — 27 findings):**
 
| # | Уязвимость | Файл | Строка (до) | Severity | Статус |
|---|-----------|------|-------------|----------|--------|
| 1 | SQL Injection (formatted query) | main.py | 102 | Critical | ✅ Исправлено |
| 2 | SQL Injection (formatted query) | main.py | 121–122 | Critical | ✅ Исправлено |
| 3 | SQL Injection (f-string) | main.py | 143 | Critical | ✅ Исправлено |
| 4 | SQL Injection (f-string DELETE) | main.py | 153 | Critical | ✅ Исправлено |
| 5 | SQL Injection (f-string UPDATE) | main.py | 270 | Critical | ✅ Исправлено |
| 6 | Command Injection (`shell=True`) | main.py | 165, 178 | Critical | ✅ Исправлено |
| 7 | Insecure Deserialization (`pickle.loads`) | main.py | 227 | Critical | ✅ Заменено на `json.loads` |
| 8 | MD5 used as password hash | main.py | 244 | High | ✅ Заменено на `bcrypt` |
| 9 | Hardcoded JWT secret | main.py | 126–130 | High | ✅ `os.getenv("JWT_SECRET")` |
| 10 | MD5 used as password hash | utils.py | 21, 26 | High | ✅ `passlib[bcrypt]` |
| 11 | Command Injection (`shell=True`) | utils.py | 42 | Critical | ✅ `shell=False` + list |
| 12 | Insecure file permissions (`0o777`) | utils.py | 55 | Medium | ✅ Изменено на `0o600` |
| 13 | SSL cert verification disabled (`verify=False`) | utils.py | 84 | High | ✅ `verify=True` |
| 14 | Privileged container (`privileged: true`) | docker-compose.yml | 20 | Critical | ✅ Удалено |
| 15 | No `no-new-privileges` для Redis | docker-compose.yml | 26 | Medium | ✅ Добавлено `security_opt` |
| 16 | Writable root filesystem (Redis) | docker-compose.yml | 26 | Medium | ✅ `read_only: true` |
| 17 | Missing `USER` в Dockerfile | Dockerfile | 17 | High | ✅ `USER app` добавлен |
| 18 | Stripe API Key в `.env` | .env | 12 | Critical | ✅ Убран из кода, только в `.env` (не коммитится) |
 
---

### Шаг 2 — Dependency Scan (Trivy)

```bash
# Сканирование зависимостей
trivy fs --scanners vuln --severity CRITICAL,HIGH .

# Сканирование Docker-образа
docker build -t econo-engine-api .
trivy image --severity CRITICAL,HIGH econo-engine-api

# Результаты:
# До:    Total: 29 (HIGH: 27, CRITICAL: 2)
# После: Total: 0
```

Основные обновления зависимостей:
`PyJWT 2.4.0 → 2.12.0`,
`aiohttp 3.8.1 → 3.13.3`,
`certifi 2022.6.15 → 2024.12.14`,
`cryptography 38.0.0 → 46.0.5`,
`pillow 9.0.0 → 12.2.0`,
`python-multipart 0.0.5 → 0.0.27`,
`starlette 0.26.1 → 0.49.3`,
`urllib3 1.26.5 → 2.7.0`.

Также для Docker image scan был удален/обновлен vulnerable runtime tooling:
`setuptools` / `wheel` / `jaraco.context`.

---

### Шаг 3 — Управление секретами

```bash
# Проверить, что .env в .gitignore
grep ".env" .gitignore

# Убедиться, что секретов нет в коде
grep -r "password\|secret\|api_key" app/ --include="*.py" | grep -v "os.getenv"

# Проверить историю коммитов через gitleaks
docker run --rm -v "$(pwd)":/repo gitleaks/gitleaks detect --source /repo -v
```

Все секреты вынесены в `.env`. Пример заполненного шаблона — `.env.example` (без реальных значений). Gitleaks secrets scan добавлен в CI/CD через GitHub Actions.

---

### Шаг 4 — CI/CD Pipeline

Файл: `.github/workflows/security.yml`

Pipeline запускается на каждый `push` и `pull_request`.

Pipeline включает 5 security gates:

```
1. Semgrep SAST          → blocking findings найдены → pipeline падает
2. Gitleaks              → секреты в коде  → pipeline падает
3. Trivy (filesystem)    → HIGH/CRITICAL CVE найдены → pipeline падает
4. Docker build          → образ собирается
5. Trivy (image scan)    → HIGH/CRITICAL CVE → pipeline падает
```
![Security Gate](https://github.com/AbylayPugashbek/devsecops-test-task/blob/main/Security_gate.png?raw=true)
---

### Шаг 5 — Hardening сервера

Приложение развёрнуто на **Ubuntu 22.04 VPS** (Oracle Cloud Free Tier).

Публичный адрес: `http://193.123.74.115`

**Проверки:**

```bash
# SSH — только ключи, root отключен, порт изменен
ssh -p 2222 <user>@193.123.74.115

# Проверка SSH-конфигурации на сервере
sudo sshd -T | grep -E "port|permitrootlogin|passwordauthentication|pubkeyauthentication"

# UFW — открыты только необходимые порты
sudo ufw status verbose

# fail2ban — активен для SSH
sudo systemctl status fail2ban
sudo fail2ban-client status sshd

# Nginx security headers
curl -I http://193.123.74.115/api/v1/health

# Ожидаемый вывод:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Content-Security-Policy: default-src 'self'; ...
# Referrer-Policy: no-referrer
```

**Конфигурация:**

- Создан отдельный пользователь для приложения / контейнер запускается не от root
- SSH: PasswordAuthentication off, PermitRootLogin no, Port 2222
- UFW: разрешены порты 2222 (SSH), 80 (HTTP), 443 (HTTPS)
- fail2ban: защита SSH
- Docker: `USER app` в Dockerfile (non-root)
- Nginx: security headers, `server_tokens off`, блокировка `/.`
- Логи: без паролей и токенов (sanitize_log_value в utils.py)

---

### Шаг 6 — DAST (OWASP ZAP)

DAST-проверка была выполнена через **OWASP ZAP Desktop**.

Проверялись:

- внешний адрес приложения: `http://193.123.74.115`
- OpenAPI endpoint: `http://193.123.74.115/openapi.json`
- отдельные API endpoints вручную через ZAP
- повторный scan после исправлений

Найденные проблемы:

| Finding | Risk | Endpoint | Статус |
|---|---|---|---|
| HTTP Only Site | Medium | `http://193.123.74.115/openapi.json` | Accepted risk |
| Application Error Disclosure | Low | `PUT /api/v1/users/10` | Fixed |
| Application Error Disclosure | Low | `POST /api/v1/users/login` | Fixed |
| Application Error Disclosure | Low | `POST /api/v1/data/import` | Fixed |
| Application Error Disclosure | Low | `POST /api/v1/users/register` | Fixed |
| Application Error Disclosure | Low | `POST /api/v1/webhooks/test` | Fixed |
| External Redirect | High | `GET /api/v1/redirect?url=` | Fixed |
| Sensitive Information in URL | Informational | `GET /api/v1/users/search?username=` | Accepted |

Исправлено:

- отключен FastAPI debug mode в production
- добавлена обработка пустого/некорректного JSON body
- вместо `500 Internal Server Error` возвращается контролируемый `400 Bad Request`
- `External Redirect` исправлен: endpoint `/api/v1/redirect` теперь разрешает только внутренние relative paths и блокирует внешние URL

Accepted risk:

- `HTTP Only Site` — принято как ограничение тестового стенда без домена/TLS
- `Sensitive Information in URL` — принято как informational, так как `username` не является секретом уровня `password`, `token`, `api_key`

Дополнительно по результатам manual review была найдена и исправлена уязвимость `Broken Access Control`.

До исправления user-management endpoints были доступны без обязательной проверки JWT-авторизации. Это позволяло выполнять прямые запросы к чужим user records.

После исправления:

- `GET /api/v1/users/{id}` теперь требует `Authorization: Bearer <token>`
- `PUT /api/v1/users/{id}` теперь требует `Authorization: Bearer <token>`
- `DELETE /api/v1/users/{id}` доступен только пользователю с ролью `admin`
- обычный пользователь может читать и обновлять только свой профиль

---

## JWT Authorization

JWT Authorization был добавлен для устранения `Broken Access Control`.  
До исправления user-management endpoints могли вызываться напрямую без проверки прав пользователя. После исправления API проверяет JWT token из заголовка `Authorization` и разрешает доступ только владельцу профиля или пользователю с ролью `admin`.

Защищенные endpoints:

| Method | Endpoint | Доступ |
|--------|----------|--------|
| GET | `/api/v1/users/{id}` | Только владелец профиля или admin |
| PUT | `/api/v1/users/{id}` | Только владелец профиля или admin |
| DELETE | `/api/v1/users/{id}` | Только admin |


Проверка без токена:

```bash
curl -i http://193.123.74.115/api/v1/users/1
```

Ожидаемый результат:

```text
401 Unauthorized
```

Получение JWT token:

```bash
curl -i -X POST "http://193.123.74.115/api/v1/users/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"apitest1","password":"Password123"}'
```

Проверка с токеном:

```bash
curl -i "http://193.123.74.115/api/v1/users/1" \
  -H "Authorization: Bearer <token>"
```

Если пользователь обращается к чужому профилю:

```text
403 Forbidden
```

Итоговый статус finding:

```text
Manual Review | Broken Access Control | High | GET/PUT/DELETE /api/v1/users/{id} | Fixed
```
---

## Ограничения

- **HTTPS** — на тестовом стенде не настроен, так как нет домена для Let's Encrypt. Для production обязательно настроить TLS.

---

## API Endpoints

| Method | Endpoint | Описание |
|--------|----------|----------|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/users/login` | Аутентификация |
| POST | `/api/v1/users/register` | Регистрация |
| GET | `/api/v1/users/search?username=` | Поиск пользователей |
| GET | `/api/v1/users/{id}` | Данные пользователя |
| PUT | `/api/v1/users/{id}` | Обновление профиля |
| DELETE | `/api/v1/users/{id}` | Удаление пользователя |
| GET | `/api/v1/tools/ping?host=` | Ping-инструмент |
| GET | `/api/v1/tools/dns-lookup?domain=` | DNS lookup |
| GET | `/api/v1/files/{path}` | Файлы из /uploads |
| POST | `/api/v1/webhooks/test` | Тест webhook URL |
| POST | `/api/v1/data/import` | Импорт JSON-данных |
| GET | `/api/v1/debug/config` | Конфигурация (безопасная) |
| GET | `/api/v1/debug/env` | Env-метаданные (только ENVIRONMENT, LOG_LEVEL) |
| GET | `/api/v1/redirect?url=` | Внутренний редирект |
