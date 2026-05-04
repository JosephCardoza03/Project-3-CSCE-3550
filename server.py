# Project 2 - JWKS Server

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import base64
import json
import jwt
import datetime
import sqlite3
import time
import os
import uuid
import threading
import hashlib

HOST = "localhost"
PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


# ---------------------------------------------------------------------------
# AES Encryption
# ---------------------------------------------------------------------------

def get_aes_key() -> bytes:
    """Derive a 32-byte AES key from the NOT_MY_KEY environment variable."""
    raw = os.environ.get("NOT_MY_KEY", "default-insecure-fallback-key-123456")
    return hashlib.sha256(raw.encode()).digest()


def encrypt_pem(pem_bytes: bytes) -> bytes:
    """Encrypt PEM bytes with AES-256-GCM. Returns nonce + ciphertext."""
    aesgcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, pem_bytes, None)


def decrypt_pem(data: bytes) -> bytes:
    """Decrypt bytes from encrypt_pem()."""
    aesgcm = AESGCM(get_aes_key())
    return aesgcm.decrypt(data[:12], data[12:], None)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    return sqlite3.connect(DB_FILE)


def init_db() -> None:
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def save_key(pem_bytes: bytes, exp: int) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypt_pem(pem_bytes), exp)
        )
        conn.commit()


def get_valid_key() -> tuple | None:
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (now,)
        ).fetchone()
    if row is None:
        return None
    return row[0], decrypt_pem(bytes(row[1]))


def get_expired_key() -> tuple | None:
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (now,)
        ).fetchone()
    if row is None:
        return None
    return row[0], decrypt_pem(bytes(row[1]))


def get_all_valid_keys() -> list:
    now = int(time.time())
    with get_db() as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?", (now,)
        ).fetchall()
    return [(kid, decrypt_pem(bytes(key))) for kid, key in rows]


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_pem() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def seed_keys() -> None:
    now = int(time.time())
    save_key(generate_pem(), now + 3600)
    save_key(generate_pem(), now - 1)


# ---------------------------------------------------------------------------
# JWKS / JWT helpers
# ---------------------------------------------------------------------------

def int_to_base64(value: int) -> str:
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    return base64.urlsafe_b64encode(bytes.fromhex(value_hex)).rstrip(b'=').decode('utf-8')


def build_jwk(kid: int, pem_bytes: bytes) -> dict:
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    numbers = private_key.private_numbers()
    return {
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "kid": str(kid),
        "n": int_to_base64(numbers.public_numbers.n),
        "e": int_to_base64(numbers.public_numbers.e),
    }


def build_jwks(rows: list) -> dict:
    return {"keys": [build_jwk(kid, pem) for kid, pem in rows]}


def build_jwt(kid: int, pem_bytes: bytes, expired: bool = False) -> str:
    now = datetime.datetime.utcnow()
    exp = now - datetime.timedelta(hours=1) if expired else now + datetime.timedelta(hours=1)
    return jwt.encode(
        {"user": "username", "exp": exp},
        pem_bytes,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )


# ---------------------------------------------------------------------------
# User registration
# ---------------------------------------------------------------------------

def register_user(username: str, email: str | None) -> str:
    """Create user with UUIDv4 password hashed via Argon2. Returns plaintext password."""
    password = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, ph.hash(password), email)
        )
        conn.commit()
    return password


def get_user_id(username: str) -> int | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# Auth logging
# ---------------------------------------------------------------------------

def log_auth_request(ip: str, user_id: int | None) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (ip, user_id)
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Rate limiter — token bucket, 10 req/sec
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Fixed-window rate limiter: allows up to `limit` requests per 1-second window.
    Any request beyond that limit in the same window returns False.
    """
    def __init__(self, limit: int):
        self.limit = limit
        self._count = 0
        self._window_start = time.monotonic()
        self._lock = threading.Lock()

    def consume(self) -> bool:
        with self._lock:
            now = time.monotonic()
            # Reset counter if we've moved into a new 1-second window
            if now - self._window_start >= 1.0:
                self._count = 0
                self._window_start = now
            if self._count < self.limit:
                self._count += 1
                return True
            return False


auth_rate_limiter = RateLimiter(limit=10)

# Track per-second request counts for stricter enforcement
_rate_window_start = time.monotonic()
_rate_window_count = 0
_rate_lock = threading.Lock()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class MyServer(BaseHTTPRequestHandler):

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        # ---- POST /register ------------------------------------------------
        if parsed_path.path == "/register":
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length) if length else b"{}")
                username = data.get("username", "").strip()
                if not username:
                    raise ValueError("username required")
                email = data.get("email", "").strip() or None
                password = register_user(username, email)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"password": password}).encode())
            except (json.JSONDecodeError, ValueError):
                self.send_response(400)
                self.end_headers()
            except Exception:
                self.send_response(409)
                self.end_headers()
            return

        # ---- POST /auth ----------------------------------------------------
        if parsed_path.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        # Rate limit check
        if not auth_rate_limiter.consume():
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Too Many Requests"}')
            return

        use_expired = "expired" in params
        row = get_expired_key() if use_expired else get_valid_key()

        if row is None:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'{"error": "no suitable key found"}')
            return

        kid, pem_bytes = row

        # Log the request — read body only if Content-Length says there is one
        client_ip = self.client_address[0] if self.client_address else "unknown"
        user_id = None
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                body = json.loads(self.rfile.read(length))
                user_id = get_user_id(body.get("username", ""))
        except Exception:
            pass
        log_auth_request(client_ip, user_id)

        token = build_jwt(kid, pem_bytes, expired=use_expired)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(token.encode())

    def do_GET(self):
        if self.path != "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        rows = get_all_valid_keys()
        body = json.dumps(build_jwks(rows)).encode()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    init_db()
    seed_keys()
    webServer = HTTPServer((HOST, PORT), MyServer)
    print(f"JWKS server running at http://{HOST}:{PORT}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
