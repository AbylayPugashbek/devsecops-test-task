# ECONO Engine API

Internal REST API service for the ECONO Engine platform.

## Quick Start

### Local Development

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Docker

```bash
docker-compose up --build
```

API will be available at `http://localhost:8000`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/users/login` | User authentication |
| POST | `/api/v1/users/register` | Register new user |
| GET | `/api/v1/users/search?username=` | Search users |
| GET | `/api/v1/users/{id}` | Get user details |
| PUT | `/api/v1/users/{id}` | Update user |
| DELETE | `/api/v1/users/{id}` | Delete user |
| GET | `/api/v1/tools/ping?host=` | Ping tool |
| GET | `/api/v1/tools/dns-lookup?domain=` | DNS lookup |
| GET | `/api/v1/files/{path}` | Get file |
| POST | `/api/v1/webhooks/test` | Test webhook |
| POST | `/api/v1/data/import` | Import data |
| GET | `/api/v1/debug/config` | Debug config |
| GET | `/api/v1/debug/env` | Environment info |
| GET | `/api/v1/redirect?url=` | URL redirect |

## Deployment

Deploy to production VPS using Docker Compose.
