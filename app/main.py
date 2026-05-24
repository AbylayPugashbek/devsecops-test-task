from fastapi import FastAPI, HTTPException, Request, Depends, Query
from fastapi.responses import JSONResponse, FileResponse
import sqlite3
import hashlib
import os
import subprocess
import requests
import logging
import jwt
import json
import base64
from datetime import datetime, timedelta, timezone
import re
from passlib.context import CryptContext


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
SECRET_KEY = os.getenv("SECRET_KEY")
API_KEY = os.getenv("API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
REDIS_URL = os.getenv("REDIS_URL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable must be set")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# ===== DEBUG MODE IN PRODUCTION (Vuln: Debug enabled) =====
app = FastAPI(title="ECONO Engine API", debug=True)

# ===== LOGGING SENSITIVE DATA (Vuln: Secrets in logs) =====
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_db():
    """Get database connection."""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn

def is_safe_hostname(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value)) and ".." not in value

def init_db():
    """Initialize database with sample data."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            api_key TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            owner_id INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            user_id INTEGER,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Vuln: Storing plaintext passwords
    if ADMIN_PASSWORD:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, email, password, role, api_key) VALUES (?, ?, ?, ?, ?)",
            (
                "admin",
                "admin@econo-engine.io",
                pwd_context.hash(ADMIN_PASSWORD),
                "admin",
                None,
            ),
    )
    conn.commit()
    conn.close()


init_db()


# ===== SQL INJECTION (Vuln: String formatting in SQL) =====
@app.get("/api/v1/users/search")
async def search_users(username: str = Query(...)):
    """Search users by username."""
    conn = get_db()
    try:
        results = conn.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ?",
            (f"%{username}%",),
        ).fetchall()
        return {"users": [dict(r) for r in results]}
    except Exception:
        logger.exception("Database error during user search")
        raise HTTPException(status_code=500, detail=f"Database error")
    finally:
        conn.close()


@app.post("/api/v1/users/login")
async def login(request: Request):
    """Authenticate user."""
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")

    # Vuln: Logging credentials
    logger.info("Login attempt for username=%s", username)

    conn = get_db()
    # Vuln: SQL Injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?",(username, password)
    user = conn.execute(query).fetchone()

    if user:
        # Vuln: Weak JWT with no expiration
        token = jwt.encode(
            {"user_id": user["id"], 
             "role": user["role"], 
             "username": user["username"],
             "exp": datetime.now(timezone.utc) + timedelta(minutes=30),},
            JWT_SECRET,
            algorithm="HS256",
        )
        # Vuln: Logging token
        logger.info("User %s logged in", username)
        return {"token": token, "role": user["role"]}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ===== BROKEN ACCESS CONTROL (Vuln: No auth check) =====
@app.get("/api/v1/users/{user_id}")
async def get_user(user_id: int):
    """Get user details - no authorization check."""
    conn = get_db()
    # Vuln: Exposing password and api_key
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        return dict(user)
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/api/v1/users/{user_id}")
async def delete_user(user_id: int):
    """Delete user - no authorization check."""
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"status": "deleted"}


# ===== COMMAND INJECTION (Vuln: Unsanitized input in shell) =====
@app.get("/api/v1/tools/ping")
async def ping_host(host: str = Query(...)):
    """Ping a host for health check."""
    if not is_safe_hostname(host):
        raise HTTPException(status_code=400, detail="Invalid host")

    try:
        result = subprocess.run(
            ["ping", "-c", "2", host],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Ping tool is not available")

    return {"stdout": result.stdout, "stderr": result.stderr}



@app.get("/api/v1/tools/dns-lookup")
async def dns_lookup(domain: str = Query(...)):
    """DNS lookup tool."""
    if not is_safe_hostname(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")

    try:
        result = subprocess.run(
            ["nslookup", domain],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="DNS lookup tool is not available")

    return {"result": result.stdout}



# ===== PATH TRAVERSAL (Vuln: No path validation) =====
@app.get("/api/v1/files/{filepath:path}")
async def get_file(filepath: str):
    """Serve files from uploads directory."""
    # Vuln: Path traversal - no sanitization of ../
    full_path = f"/app/uploads/{filepath}"
    logger.debug(f"Serving file: {full_path}")
    if os.path.exists(full_path):
        return FileResponse(full_path)
    raise HTTPException(status_code=404, detail="File not found")


# ===== SSRF (Vuln: No URL validation) =====
@app.post("/api/v1/webhooks/test")
async def test_webhook(request: Request):
    """Test a webhook URL."""
    data = await request.json()
    url = data.get("url", "")

    # Vuln: SSRF - can access internal services, cloud metadata, etc.
    logger.info(f"Testing webhook: {url}")
    try:
        response = requests.get(url, timeout=5)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:1000],
        }
    except Exception as e:
        return {"error": str(e)}


# ===== INSECURE DESERIALIZATION (Vuln: Pickle from user input) =====
@app.post("/api/v1/data/import")
async def import_data(request: Request):
    """Import serialized data."""
    data = await request.json()
    encoded = data.get("payload", "")

    # Vuln: Insecure deserialization
    try:
        decoded = base64.b64decode(encoded)
        obj = json.loads(decoded.decode("utf-8"))
        return {"imported": str(obj)}
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Import payload must be base64-encoded JSON")



# ===== WEAK CRYPTOGRAPHY (Vuln: MD5 for passwords) =====
@app.post("/api/v1/users/register")
async def register(request: Request):
    """Register a new user."""
    data = await request.json()
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")

    if not username or len(username) < 3:
        raise HTTPException(status_code=400, detail="Username too short")

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        raise HTTPException(status_code=400, detail="Invalid email")

    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password too short")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain uppercase")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must contain digit")

    password_hash = pwd_context.hash(password)


    # Vuln: Logging password
    logger.info("Registering user: %s", username)


    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        conn.commit()
        return {"status": "created", "username": username}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===== MASS ASSIGNMENT (Vuln: User can set their own role) =====
@app.put("/api/v1/users/{user_id}")
async def update_user(user_id: int, request: Request):
    """Update user profile."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")

    allowed_fields = {"email"}
    updates = {key: value for key, value in data.items() if key in allowed_fields}

    if not updates:
        raise HTTPException(status_code=400, detail="No updatable fields provided")

    conn = get_db()
    if "email" in updates:
        conn.execute(
            "UPDATE users SET email = ? WHERE id = ?",
            (updates["email"], user_id),
        )
    conn.commit()
    return {"status": "updated"}


# ===== INFORMATION DISCLOSURE =====
@app.get("/api/v1/debug/config")
async def get_config():
    """Return non-sensitive runtime configuration."""
    return {
        "debug": False,
        "environment": os.getenv("ENVIRONMENT", "development"),
    }


@app.get("/api/v1/debug/env")
async def get_env():
    """Return non-sensitive environment metadata."""
    allowed_keys = {"ENVIRONMENT", "LOG_LEVEL"}
    return {key: os.environ[key] for key in allowed_keys if key in os.environ}


# ===== OPEN REDIRECT (Vuln: No URL validation) =====
@app.get("/api/v1/redirect")
async def redirect_url(url: str = Query(...)):
    """Redirect to external URL."""
    # Vuln: Open redirect
    from starlette.responses import RedirectResponse
    return RedirectResponse(url=url)


# ===== NO RATE LIMITING, NO CORS CONFIG =====
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.2.3",
        "database": "connected",
        "server": "econo-prod-01",  # Vuln: Exposing server info
    }


if __name__ == "__main__":
    import uvicorn
    # Vuln: Binding to all interfaces
    uvicorn.run(app, host="0.0.0.0", port=8000)
