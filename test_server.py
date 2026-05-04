"""
Test suite for the JWKS server (Project 2).
Run with:  pytest --cov=server --cov-report=term-missing
"""

import time
import json
import os
import pytest
from io import BytesIO
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Make sure NOT_MY_KEY is set before importing server
# ---------------------------------------------------------------------------
os.environ.setdefault("NOT_MY_KEY", "test-secret-key-for-unit-tests")

import server as srv


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point DB_FILE at a temp file for every test so tests don't share state."""
    monkeypatch.setattr(srv, "DB_FILE", str(tmp_path / "test.db"))
    # Reset the rate limiter before each test so tests are independent
    srv.auth_rate_limiter._count = 0
    srv.auth_rate_limiter._window_start = __import__("time").monotonic()
    srv.init_db()


@pytest.fixture()
def seeded():
    """Seed one valid + one expired key."""
    srv.seed_keys()


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

class TestInitDb:
    def test_creates_keys_table(self):
        with srv.get_db() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
            ).fetchone()
        assert result is not None

    def test_creates_users_table(self):
        with srv.get_db() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
            ).fetchone()
        assert result is not None

    def test_creates_auth_logs_table(self):
        with srv.get_db() as conn:
            result = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs'"
            ).fetchone()
        assert result is not None

    def test_is_idempotent(self):
        srv.init_db()
        srv.init_db()


# ---------------------------------------------------------------------------
# AES encryption helpers
# ---------------------------------------------------------------------------

class TestAesEncryption:
    def test_encrypt_returns_bytes(self):
        pem = srv.generate_pem()
        encrypted = srv.encrypt_pem(pem)
        assert isinstance(encrypted, bytes)

    def test_encrypted_differs_from_plaintext(self):
        pem = srv.generate_pem()
        encrypted = srv.encrypt_pem(pem)
        assert encrypted != pem

    def test_decrypt_round_trip(self):
        pem = srv.generate_pem()
        assert srv.decrypt_pem(srv.encrypt_pem(pem)) == pem

    def test_unique_nonces(self):
        """Two encryptions of the same PEM should produce different ciphertexts."""
        pem = srv.generate_pem()
        assert srv.encrypt_pem(pem) != srv.encrypt_pem(pem)

    def test_missing_env_var_uses_fallback(self, monkeypatch):
        monkeypatch.delenv("NOT_MY_KEY", raising=False)
        # Should NOT raise - uses a fallback key so server can still start
        key = srv.get_aes_key()
        assert isinstance(key, bytes) and len(key) == 32


# ---------------------------------------------------------------------------
# Key storage helpers
# ---------------------------------------------------------------------------

class TestSaveKey:
    def test_inserts_row(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        assert count == 1

    def test_stored_value_is_encrypted(self):
        """Raw bytes in DB should NOT equal the plaintext PEM."""
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        with srv.get_db() as conn:
            raw = conn.execute("SELECT key FROM keys").fetchone()[0]
        assert bytes(raw) != pem

    def test_kid_autoincrements(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        srv.save_key(pem, int(time.time()) + 7200)
        with srv.get_db() as conn:
            kids = [r[0] for r in conn.execute("SELECT kid FROM keys").fetchall()]
        assert kids == [1, 2]


class TestGetValidKey:
    def test_returns_none_when_empty(self):
        assert srv.get_valid_key() is None

    def test_returns_valid_key(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        row = srv.get_valid_key()
        assert row is not None
        # Returned PEM should match the original (decrypted correctly)
        assert row[1] == pem

    def test_skips_expired_keys(self):
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        assert srv.get_valid_key() is None


class TestGetExpiredKey:
    def test_returns_none_when_empty(self):
        assert srv.get_expired_key() is None

    def test_returns_expired_key(self):
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        assert srv.get_expired_key() is not None

    def test_skips_valid_keys(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        assert srv.get_expired_key() is None


class TestGetAllValidKeys:
    def test_empty_db(self):
        assert srv.get_all_valid_keys() == []

    def test_only_returns_valid(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        rows = srv.get_all_valid_keys()
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

class TestGeneratePem:
    def test_is_pem_bytes(self):
        pem = srv.generate_pem()
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_generates_unique_keys(self):
        assert srv.generate_pem() != srv.generate_pem()


class TestSeedKeys:
    def test_inserts_two_keys(self):
        srv.seed_keys()
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        assert count == 2

    def test_one_valid_one_expired(self):
        srv.seed_keys()
        assert srv.get_valid_key() is not None
        assert srv.get_expired_key() is not None


# ---------------------------------------------------------------------------
# JWKS / JWT helpers
# ---------------------------------------------------------------------------

class TestIntToBase64:
    def test_known_exponent(self):
        assert srv.int_to_base64(65537) == "AQAB"

    def test_no_padding_characters(self):
        assert "=" not in srv.int_to_base64(255)

    def test_odd_length_hex(self):
        result = srv.int_to_base64(1)
        assert isinstance(result, str)


class TestBuildJwk:
    def test_contains_required_fields(self):
        pem = srv.generate_pem()
        jwk = srv.build_jwk(1, pem)
        for field in ("alg", "kty", "use", "kid", "n", "e"):
            assert field in jwk

    def test_kty_is_rsa(self):
        pem = srv.generate_pem()
        assert srv.build_jwk(1, pem)["kty"] == "RSA"

    def test_kid_is_string(self):
        pem = srv.generate_pem()
        assert srv.build_jwk(42, pem)["kid"] == "42"


class TestBuildJwks:
    def test_empty_rows(self):
        assert srv.build_jwks([]) == {"keys": []}

    def test_single_key(self):
        pem = srv.generate_pem()
        srv.save_key(pem, int(time.time()) + 3600)
        rows = srv.get_all_valid_keys()
        jwks = srv.build_jwks(rows)
        assert len(jwks["keys"]) == 1

    def test_multiple_keys(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        srv.save_key(srv.generate_pem(), int(time.time()) + 7200)
        rows = srv.get_all_valid_keys()
        assert len(srv.build_jwks(rows)["keys"]) == 2


class TestBuildJwt:
    def test_returns_string(self):
        pem = srv.generate_pem()
        token = srv.build_jwt(1, pem)
        assert isinstance(token, str)

    def test_is_valid_jwt_format(self):
        pem = srv.generate_pem()
        token = srv.build_jwt(1, pem)
        assert token.count(".") == 2

    def test_expired_jwt_format(self):
        pem = srv.generate_pem()
        token = srv.build_jwt(1, pem, expired=True)
        assert token.count(".") == 2


# ---------------------------------------------------------------------------
# User registration helpers
# ---------------------------------------------------------------------------

class TestRegisterUser:
    def test_returns_uuid_password(self):
        password = srv.register_user("alice", "alice@example.com")
        import uuid
        parsed = uuid.UUID(password, version=4)
        assert str(parsed) == password

    def test_user_stored_in_db(self):
        srv.register_user("bob", "bob@example.com")
        with srv.get_db() as conn:
            row = conn.execute("SELECT username FROM users WHERE username='bob'").fetchone()
        assert row is not None

    def test_password_hash_not_plaintext(self):
        password = srv.register_user("carol", "carol@example.com")
        with srv.get_db() as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE username='carol'").fetchone()
        assert row[0] != password

    def test_duplicate_username_raises(self):
        srv.register_user("dave", "dave@example.com")
        with pytest.raises(Exception):
            srv.register_user("dave", "dave2@example.com")


class TestGetUserId:
    def test_returns_id_for_existing_user(self):
        srv.register_user("eve", "eve@example.com")
        uid = srv.get_user_id("eve")
        assert uid is not None
        assert isinstance(uid, int)

    def test_returns_none_for_missing_user(self):
        assert srv.get_user_id("nobody") is None


# ---------------------------------------------------------------------------
# Auth logging helpers
# ---------------------------------------------------------------------------

class TestLogAuthRequest:
    def test_inserts_log_row(self):
        srv.log_auth_request("127.0.0.1", None)
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
        assert count == 1

    def test_stores_ip(self):
        srv.log_auth_request("10.0.0.1", None)
        with srv.get_db() as conn:
            row = conn.execute("SELECT request_ip FROM auth_logs").fetchone()
        assert row[0] == "10.0.0.1"

    def test_stores_user_id(self):
        srv.register_user("frank", "frank@example.com")
        uid = srv.get_user_id("frank")
        srv.log_auth_request("127.0.0.1", uid)
        with srv.get_db() as conn:
            row = conn.execute("SELECT user_id FROM auth_logs").fetchone()
        assert row[0] == uid

    def test_null_user_id_allowed(self):
        srv.log_auth_request("192.168.1.1", None)
        with srv.get_db() as conn:
            row = conn.execute("SELECT user_id FROM auth_logs").fetchone()
        assert row[0] is None


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = srv.RateLimiter(limit=5)
        for _ in range(5):
            assert limiter.consume() is True

    def test_blocks_over_limit(self):
        limiter = srv.RateLimiter(limit=3)
        limiter.consume(); limiter.consume(); limiter.consume()
        assert limiter.consume() is False

    def test_resets_after_window(self):
        limiter = srv.RateLimiter(limit=2)
        limiter.consume(); limiter.consume()        # drain
        assert limiter.consume() is False
        time.sleep(1.05)                            # wait for new window
        assert limiter.consume() is True


# ---------------------------------------------------------------------------
# HTTP handler helpers
# ---------------------------------------------------------------------------

def make_handler(method: str, path: str, body: bytes = b"", headers: dict = None):
    """Create a MyServer instance without a real socket."""
    handler = srv.MyServer.__new__(srv.MyServer)
    handler.path = path
    handler.wfile = BytesIO()
    handler.rfile = BytesIO(body)
    handler.headers = {"Content-Length": str(len(body))}
    if headers:
        handler.headers.update(headers)
    handler.client_address = ("127.0.0.1", 0)
    handler.server = None
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.request_version = "HTTP/1.1"
    handler.command = method
    return handler


def get_raw_body(handler) -> str:
    handler.wfile.seek(0)
    raw = handler.wfile.read().decode()
    parts = raw.split("\r\n\r\n", 1)
    return parts[1].strip() if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# GET handler
# ---------------------------------------------------------------------------

class TestGetHandler:
    def test_jwks_returns_200(self):
        h = make_handler("GET", "/.well-known/jwks.json")
        h.do_GET()
        h.wfile.seek(0)
        assert b"200" in h.wfile.read()

    def test_jwks_empty(self):
        h = make_handler("GET", "/.well-known/jwks.json")
        h.do_GET()
        assert get_raw_body(h) == '{"keys": []}'

    def test_jwks_with_valid_key(self, seeded):
        h = make_handler("GET", "/.well-known/jwks.json")
        h.do_GET()
        data = json.loads(get_raw_body(h))
        assert len(data["keys"]) == 1

    def test_unknown_path_405(self):
        h = make_handler("GET", "/unknown")
        h.do_GET()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()


# ---------------------------------------------------------------------------
# POST /auth handler
# ---------------------------------------------------------------------------

class TestPostAuthHandler:
    def test_auth_returns_jwt(self, seeded):
        h = make_handler("POST", "/auth")
        h.do_POST()
        body = get_raw_body(h)
        assert body.count(".") == 2

    def test_auth_expired_returns_jwt(self, seeded):
        h = make_handler("POST", "/auth?expired=true")
        h.do_POST()
        body = get_raw_body(h)
        assert body.count(".") == 2

    def test_auth_no_valid_key_500(self):
        srv.save_key(srv.generate_pem(), int(time.time()) - 1)
        h = make_handler("POST", "/auth")
        h.do_POST()
        h.wfile.seek(0)
        assert b"500" in h.wfile.read()

    def test_auth_no_expired_key_500(self):
        srv.save_key(srv.generate_pem(), int(time.time()) + 3600)
        h = make_handler("POST", "/auth?expired=true")
        h.do_POST()
        h.wfile.seek(0)
        assert b"500" in h.wfile.read()

    def test_auth_logs_request(self, seeded):
        h = make_handler("POST", "/auth")
        h.do_POST()
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
        assert count == 1

    def test_auth_logs_user_id_when_username_provided(self, seeded):
        srv.register_user("grace", "grace@example.com")
        body = json.dumps({"username": "grace"}).encode()
        h = make_handler("POST", "/auth", body=body)
        h.do_POST()
        with srv.get_db() as conn:
            row = conn.execute("SELECT user_id FROM auth_logs").fetchone()
        assert row[0] is not None

    def test_auth_rate_limit_returns_429(self, seeded):
        # Force the rate limiter to deny by mocking consume() to return False
        with patch.object(srv.auth_rate_limiter, "consume", return_value=False):
            h = make_handler("POST", "/auth")
            h.do_POST()
            h.wfile.seek(0)
            assert b"429" in h.wfile.read()

    def test_rate_limited_requests_not_logged(self, seeded):
        with patch.object(srv.auth_rate_limiter, "consume", return_value=False):
            h = make_handler("POST", "/auth")
            h.do_POST()
        with srv.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0]
        assert count == 0

    def test_unknown_path_405(self):
        h = make_handler("POST", "/unknown")
        h.do_POST()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()


# ---------------------------------------------------------------------------
# POST /register handler
# ---------------------------------------------------------------------------

class TestPostRegisterHandler:
    def test_register_returns_201(self):
        body = json.dumps({"username": "henry", "email": "henry@example.com"}).encode()
        h = make_handler("POST", "/register", body=body)
        h.do_POST()
        h.wfile.seek(0)
        assert b"201" in h.wfile.read()

    def test_register_returns_password(self):
        body = json.dumps({"username": "irene", "email": "irene@example.com"}).encode()
        h = make_handler("POST", "/register", body=body)
        h.do_POST()
        data = json.loads(get_raw_body(h))
        assert "password" in data
        assert len(data["password"]) == 36  # UUID format: 8-4-4-4-12

    def test_register_stores_user(self):
        body = json.dumps({"username": "jack", "email": "jack@example.com"}).encode()
        h = make_handler("POST", "/register", body=body)
        h.do_POST()
        assert srv.get_user_id("jack") is not None

    def test_register_duplicate_returns_409(self):
        body = json.dumps({"username": "kate", "email": "kate@example.com"}).encode()
        make_handler("POST", "/register", body=body).do_POST()
        h = make_handler("POST", "/register", body=body)
        h.do_POST()
        h.wfile.seek(0)
        assert b"409" in h.wfile.read()

    def test_register_bad_json_returns_400(self):
        h = make_handler("POST", "/register", body=b"not-json")
        h.do_POST()
        h.wfile.seek(0)
        assert b"400" in h.wfile.read()

    def test_register_missing_username_returns_400(self):
        body = json.dumps({"email": "nousername@example.com"}).encode()
        h = make_handler("POST", "/register", body=body)
        h.do_POST()
        h.wfile.seek(0)
        assert b"400" in h.wfile.read()


# ---------------------------------------------------------------------------
# Other HTTP methods
# ---------------------------------------------------------------------------

class TestOtherMethods:
    def test_put_405(self):
        h = make_handler("PUT", "/auth")
        h.do_PUT()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()

    def test_patch_405(self):
        h = make_handler("PATCH", "/auth")
        h.do_PATCH()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()

    def test_delete_405(self):
        h = make_handler("DELETE", "/auth")
        h.do_DELETE()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()

    def test_head_405(self):
        h = make_handler("HEAD", "/auth")
        h.do_HEAD()
        h.wfile.seek(0)
        assert b"405" in h.wfile.read()
