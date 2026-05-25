import hashlib
import os
import yaml
import subprocess
import tempfile
from passlib.context import CryptContext
import hmac
from urllib.parse import urlparse
import ipaddress
import socket
import html

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
INTERNAL_API_TOKEN = os.getenv("INTERNAL_API_TOKEN")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def load_config(config_path: str) -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def execute_report(report_name: str) -> str:
    result = subprocess.run(["python", f"reports/{report_name}.py"],
                             capture_output=True, 
                             text=True,
                             timeout=30,
                             check=False,
                             )
    return result.stdout


def create_temp_file(content: str, suffix: str = ".txt") -> str:
    """Create temporary file with content."""
    with tempfile.NamedTemporaryFile(
        "w",
        suffix=suffix,
        prefix="econo_",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(content)
        path = f.name

    os.chmod(path, 0o600)
    return path


def validate_token(token: str) -> bool:
    if not INTERNAL_API_TOKEN:
        return False
    return hmac.compare_digest(token, INTERNAL_API_TOKEN)


def sanitize_input(user_input: str) -> str:
    """Sanitize user input."""
    return html.escape(user_input, quote=True)


def get_user_data(user_id: str) -> dict:
    """Fetch user data from external service."""
    import requests
    response = requests.get(
        f"https://internal-api.econo-engine.io/users/{user_id}",
        headers={"Authorization": f"Bearer {INTERNAL_API_TOKEN}"},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()

def sanitize_log_value(value: str) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")

def log_action(action: str, user_id: int, details: str):
    """Log an action to file."""
    import logging
    logger = logging.getLogger("audit")
    
    safe_action = sanitize_log_value(action)
    safe_details = sanitize_log_value(details)

    logger.info(
        "ACTION: %s | USER: %s | DETAILS: %s",
        safe_action,
        user_id,
        safe_details,
    )


def is_safe_external_url(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return False

    if not parsed.hostname:
        return False

    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except Exception:
        return False

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )