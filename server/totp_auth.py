"""Persistent, offline TOTP authentication for the camera manager."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LOG = logging.getLogger("cam-auth")
SESSION_TTL = 48 * 60 * 60
DEFAULT_ABSOLUTE_TTL = 30 * 24 * 60 * 60
TOTP_INTERVAL = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1


class AuthError(RuntimeError):
    def __init__(self, detail: str, status: int = 401, retry_after: int | None = None):
        super().__init__(detail)
        self.detail = detail
        self.status = status
        self.retry_after = retry_after


class AuthManager:
    """Persistent sessions, rate limiting, replay prevention, and TOTP state."""

    def __init__(self, data_dir: Path, session_ttl: int = SESSION_TTL,
                 absolute_ttl: int | None = DEFAULT_ABSOLUTE_TTL):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.session_ttl = int(session_ttl)
        self.absolute_ttl = None if absolute_ttl in (None, 0) else int(absolute_ttl)
        self.key_path = self.data_dir / "auth.key"
        self.state_path = self.data_dir / "auth.json"
        self.init_path = self.data_dir / "auth-init.json"
        self.pending_path = self.data_dir / "auth-pending.json"
        self.db_path = self.data_dir / "auth.sqlite3"
        self._ensure_key()
        self._ensure_db()

    def _ensure_key(self) -> None:
        if self.key_path.exists():
            if self.key_path.stat().st_mode & 0o077:
                os.chmod(self.key_path, 0o600)
            return
        temp = self.key_path.with_suffix(".new")
        temp.write_bytes(Fernet.generate_key())
        os.chmod(temp, 0o600)
        os.replace(temp, self.key_path)

    def _fernet(self) -> Fernet:
        return Fernet(self.key_path.read_bytes().strip())

    def _ensure_db(self) -> None:
        os.chmod(self.data_dir, 0o700)
        with self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    csrf TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    absolute_expires_at INTEGER,
                    last_interaction_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_expires_idx
                    ON sessions(expires_at);
                CREATE TABLE IF NOT EXISTS used_steps (
                    step INTEGER PRIMARY KEY,
                    used_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rate_limits (
                    key TEXT PRIMARY KEY,
                    window_start INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    source_ip TEXT
                );
                """
            )
        os.chmod(self.db_path, 0o600)

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @contextmanager
    def _connection(self):
        db = self._db()
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        temp = path.with_suffix(".new")
        with temp.open("w", encoding="utf-8") as handle:
            os.chmod(temp, 0o600)
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any] | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None

    @staticmethod
    def _hash_token(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _clean_code(value: Any) -> str:
        code = str(value or "").strip()
        if len(code) != TOTP_DIGITS or not code.isdigit():
            raise AuthError("请输入6位验证码", 400)
        return code

    @staticmethod
    def _totp(secret: str) -> pyotp.TOTP:
        return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL,
                          digest=hashlib.sha1)

    @staticmethod
    def _svg_qr(value: str) -> str:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=5,
            border=4,
        )
        qr.add_data(value)
        qr.make(fit=True)
        image = qr.make_image(image_factory=SvgPathImage)
        rendered = image.to_string()
        return rendered.decode("utf-8") if isinstance(rendered, bytes) else rendered

    def state(self) -> str:
        record = self._read_json(self.state_path)
        if record and record.get("state") == "bound" and record.get("secret_encrypted"):
            return "bound"
        if self._read_json(self.pending_path):
            return "pending"
        return "uninitialized"

    def public_status(self) -> dict[str, Any]:
        result = {"state": self.state(), "session_ttl_seconds": self.session_ttl}
        if self.absolute_ttl is not None:
            result["absolute_ttl_seconds"] = self.absolute_ttl
        return result

    def _secret(self) -> str:
        record = self._read_json(self.state_path)
        if not record or record.get("state") != "bound":
            raise AuthError("TOTP尚未绑定，请通过服务器本地CLI初始化", 503)
        try:
            return self._fernet().decrypt(record["secret_encrypted"].encode()).decode()
        except (KeyError, InvalidToken, UnicodeDecodeError) as exc:
            raise AuthError("TOTP认证数据损坏，请使用本地备份恢复", 500) from exc

    def _pending_secret(self, record: dict[str, Any]) -> str:
        try:
            return self._fernet().decrypt(record["secret_encrypted"].encode()).decode()
        except (KeyError, InvalidToken, UnicodeDecodeError) as exc:
            raise AuthError("临时绑定数据损坏，请重新初始化", 500) from exc

    def initialize_token(self, lifetime: int = 15 * 60) -> tuple[str, int]:
        if self.state() == "bound":
            raise AuthError("TOTP已经绑定；手机丢失时请使用本地恢复命令", 409)
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + lifetime
        self._atomic_json(self.init_path, {
            "token_hash": self._hash_token(token),
            "created_at": int(time.time()),
            "expires_at": expires,
        })
        try:
            self.pending_path.unlink()
        except FileNotFoundError:
            pass
        return token, expires

    def _valid_init_token(self, token: str) -> bool:
        record = self._read_json(self.init_path)
        if not record or int(record.get("expires_at", 0)) < int(time.time()):
            return False
        return hmac.compare_digest(record.get("token_hash", ""), self._hash_token(token))

    def _provisioning(self, secret: str) -> dict[str, str]:
        uri = self._totp(secret).provisioning_uri(
            name="admin",
            issuer_name="MuYu Camera",
        )
        return {"otpauth_uri": uri, "secret": secret, "qr_svg": self._svg_qr(uri)}

    def begin_binding(self, token: str) -> dict[str, Any]:
        if not self._valid_init_token(token):
            raise AuthError("初始化授权无效或已过期", 403)
        if self.state() == "bound":
            raise AuthError("TOTP已经绑定", 409)
        secret = pyotp.random_base32(length=32)
        expires = int(time.time()) + 15 * 60
        self._atomic_json(self.pending_path, {
            "kind": "initial",
            "token_hash": self._hash_token(token),
            "secret_encrypted": self._fernet().encrypt(secret.encode()).decode(),
            "created_at": int(time.time()),
            "expires_at": expires,
        })
        return {**self._provisioning(secret), "expires_at": expires}

    def confirm_binding(self, token: str, code: Any) -> None:
        if not self._valid_init_token(token):
            raise AuthError("初始化授权无效或已过期", 403)
        pending = self._read_json(self.pending_path)
        if not pending or pending.get("kind") != "initial":
            raise AuthError("请先开始绑定", 409)
        if int(pending.get("expires_at", 0)) < int(time.time()):
            raise AuthError("绑定二维码已过期，请重新初始化", 410)
        if not hmac.compare_digest(pending.get("token_hash", ""), self._hash_token(token)):
            raise AuthError("绑定授权不匹配", 403)
        secret = self._pending_secret(pending)
        if not self._verify_secret(secret, code):
            raise AuthError("验证码错误或已过期", 401)
        self._write_bound(secret)
        self._remove(self.pending_path)
        self._remove(self.init_path)
        self.invalidate_all()
        self._audit("totp_bound", None)

    def _write_bound(self, secret: str) -> None:
        self._atomic_json(self.state_path, {
            "version": 1,
            "state": "bound",
            "account": "admin",
            "issuer": "MuYu Camera",
            "secret_encrypted": self._fernet().encrypt(secret.encode()).decode(),
            "bound_at": int(time.time()),
        })
        # A new secret is a new credential generation; replay state from the
        # previous secret must not block the first login with the new device.
        with self._connection() as db:
            db.execute("DELETE FROM used_steps")

    @staticmethod
    def _remove(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def _verify_secret(self, secret: str, code: Any) -> bool:
        try:
            code = self._clean_code(code)
        except AuthError:
            return False
        now = int(time.time())
        totp = self._totp(secret)
        for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            timestamp = (now // TOTP_INTERVAL + offset) * TOTP_INTERVAL
            if totp.verify(
                code,
                for_time=datetime_from_timestamp(timestamp),
                valid_window=0,
            ):
                return True
        return False

    def _matching_step(self, secret: str, code: str, now: int) -> int | None:
        totp = self._totp(secret)
        for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
            step = now // TOTP_INTERVAL + offset
            if totp.verify(
                code,
                for_time=datetime_from_timestamp(step * TOTP_INTERVAL),
                valid_window=0,
            ):
                return step
        return None

    def _audit(self, event: str, source_ip: str | None) -> None:
        now = int(time.time())
        with self._connection() as db:
            db.execute("INSERT INTO audit(event, created_at, source_ip) VALUES (?, ?, ?)",
                       (event, now, source_ip))
            db.execute("DELETE FROM audit WHERE id NOT IN "
                       "(SELECT id FROM audit ORDER BY id DESC LIMIT 10000)")
        LOG.info("auth_event=%s source=%s", event, source_ip or "-")

    def _rate_status_locked(self, db: sqlite3.Connection, key: str, now: int,
                            limit: int) -> int:
        row = db.execute("SELECT * FROM rate_limits WHERE key=?", (key,)).fetchone()
        if not row:
            return 0
        if now - int(row["window_start"]) >= 60:
            db.execute("DELETE FROM rate_limits WHERE key=?", (key,))
            return 0
        if int(row["blocked_until"]) > now:
            return int(row["blocked_until"]) - now
        if int(row["attempts"]) >= limit:
            return min(60, max(2, 2 ** min(int(row["attempts"]) - limit + 1, 5)))
        return 0

    def _record_failure_locked(self, db: sqlite3.Connection, key: str, now: int,
                               limit: int) -> None:
        row = db.execute("SELECT * FROM rate_limits WHERE key=?", (key,)).fetchone()
        if not row or now - int(row["window_start"]) >= 60:
            window_start, attempts, blocked = now, 1, 0
        else:
            window_start = int(row["window_start"])
            attempts = int(row["attempts"]) + 1
            blocked = int(row["blocked_until"])
        if attempts >= limit:
            blocked = max(blocked, now + min(60, 2 ** min(attempts - limit + 1, 5)))
        db.execute(
            "INSERT INTO rate_limits(key, window_start, attempts, blocked_until) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET window_start=excluded.window_start, "
            "attempts=excluded.attempts, blocked_until=excluded.blocked_until",
            (key, window_start, attempts, blocked),
        )

    def login(self, code: Any, source_ip: str) -> tuple[str, str, int]:
        if self.state() != "bound":
            raise AuthError("TOTP尚未绑定，请通过服务器本地CLI初始化", 503)
        code = self._clean_code(code)
        now = int(time.time())
        ip_key = "ip:" + (source_ip or "unknown")
        global_key = "global"
        secret = self._secret()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            retry = max(
                self._rate_status_locked(db, ip_key, now, 5),
                self._rate_status_locked(db, global_key, now, 40),
            )
            if retry:
                db.execute("COMMIT")
                raise AuthError("尝试次数过多，请稍后再试", 429, retry)
            step = self._matching_step(secret, code, now)
            if step is None:
                self._record_failure_locked(db, ip_key, now, 5)
                self._record_failure_locked(db, global_key, now, 40)
                db.execute("COMMIT")
                self._audit("totp_login_failure", source_ip)
                raise AuthError("验证码错误或已过期", 401)
            db.execute("DELETE FROM used_steps WHERE used_at < ?", (now - 6 * 60 * 60,))
            inserted = db.execute(
                "INSERT OR IGNORE INTO used_steps(step, used_at) VALUES (?, ?)",
                (step, now),
            ).rowcount
            if inserted != 1:
                self._record_failure_locked(db, ip_key, now, 5)
                db.execute("COMMIT")
                self._audit("totp_login_replay", source_ip)
                raise AuthError("验证码已使用，请等待下一组验证码", 401)
            token = secrets.token_urlsafe(32)
            token_hash = self._hash_token(token)
            csrf = secrets.token_urlsafe(24)
            expires = now + self.session_ttl
            absolute = now + self.absolute_ttl if self.absolute_ttl is not None else None
            if absolute is not None:
                expires = min(expires, absolute)
            db.execute(
                "INSERT INTO sessions(token_hash, csrf, created_at, expires_at, "
                "absolute_expires_at, last_interaction_at) VALUES (?, ?, ?, ?, ?, ?)",
                (token_hash, csrf, now, expires, absolute, now),
            )
            db.execute("DELETE FROM rate_limits WHERE key=?", (ip_key,))
            db.execute("COMMIT")
        self._audit("totp_login_success", source_ip)
        return token, csrf, expires

    def session(self, raw_token: str | None) -> dict[str, Any] | None:
        if not raw_token:
            return None
        token_hash = self._hash_token(raw_token)
        now = int(time.time())
        with self._connection() as db:
            row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
            if not row:
                return None
            if int(row["expires_at"]) <= now:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                return None
            return dict(row)

    def should_slide(self, method: str, path: str) -> bool:
        if method.upper() != "POST" or not path.startswith("/api/"):
            return False
        if path in {"/api/login", "/api/logout", "/api/auth/bind/start",
                    "/api/auth/bind/confirm"}:
            return False
        if path.startswith("/api/auth/status"):
            return False
        return path in {
            "/api/discover",
            "/api/device",
            "/api/recording",
            "/api/ptz",
            "/api/wifi",
            "/api/auth/rotate/start",
            "/api/auth/rotate/confirm",
        } or path.startswith("/api/playback/") and path.endswith("/prepare")

    def slide(self, raw_token: str, only_if_current: int | None = None) -> dict[str, Any] | None:
        token_hash = self._hash_token(raw_token)
        now = int(time.time())
        requested = now + self.session_ttl
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
            if not row or int(row["expires_at"]) <= now:
                db.execute("COMMIT")
                return None
            if only_if_current is not None and int(row["expires_at"]) != only_if_current:
                db.execute("COMMIT")
                return dict(row)
            absolute = row["absolute_expires_at"]
            if absolute is not None:
                requested = min(requested, int(absolute))
            new_expires = max(int(row["expires_at"]), requested)
            db.execute(
                "UPDATE sessions SET expires_at=?, last_interaction_at=? WHERE token_hash=?",
                (new_expires, now, token_hash),
            )
            row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
            db.execute("COMMIT")
            return dict(row)

    def logout(self, raw_token: str | None) -> None:
        if raw_token:
            with self._connection() as db:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (self._hash_token(raw_token),))

    def invalidate_all(self) -> None:
        with self._connection() as db:
            db.execute("DELETE FROM sessions")

    def rotate_start(self, current_code: Any, raw_session: str) -> dict[str, Any]:
        if self.state() != "bound" or not self.session(raw_session):
            raise AuthError("登录状态已失效，请重新登录", 401)
        if not self._verify_secret(self._secret(), current_code):
            raise AuthError("当前验证码错误或已过期", 401)
        secret = pyotp.random_base32(length=32)
        expires = int(time.time()) + 15 * 60
        self._atomic_json(self.pending_path, {
            "kind": "rotate",
            "session_hash": self._hash_token(raw_session),
            "secret_encrypted": self._fernet().encrypt(secret.encode()).decode(),
            "created_at": int(time.time()),
            "expires_at": expires,
        })
        return {**self._provisioning(secret), "expires_at": expires}

    def rotate_confirm(self, new_code: Any, raw_session: str) -> None:
        pending = self._read_json(self.pending_path)
        if not pending or pending.get("kind") != "rotate":
            raise AuthError("请先开始更换验证器", 409)
        if int(pending.get("expires_at", 0)) < int(time.time()):
            raise AuthError("更换验证器已过期，请重新开始", 410)
        if not hmac.compare_digest(pending.get("session_hash", ""), self._hash_token(raw_session)):
            raise AuthError("更换验证器会话不匹配", 403)
        secret = self._pending_secret(pending)
        if not self._verify_secret(secret, new_code):
            raise AuthError("新设备验证码错误或已过期", 401)
        self._write_bound(secret)
        self._remove(self.pending_path)
        self.invalidate_all()
        self._audit("totp_rotated", None)

    @staticmethod
    def _backup_key(passphrase: str, salt: bytes) -> bytes:
        if not passphrase:
            raise AuthError("备份口令不能为空", 400)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

    def backup(self, path: Path, passphrase: str) -> None:
        record = self._read_json(self.state_path)
        if not record or record.get("state") != "bound":
            raise AuthError("只有已绑定的认证数据可以备份", 409)
        salt = os.urandom(16)
        payload = json.dumps({
            "version": 1,
            "auth_key": self.key_path.read_text(encoding="ascii"),
            "auth_state": record,
        }, ensure_ascii=False).encode("utf-8")
        encrypted = Fernet(self._backup_key(passphrase, salt)).encrypt(payload)
        output = {"version": 1, "salt": base64.b64encode(salt).decode(), "ciphertext": encrypted.decode()}
        self._atomic_json(Path(path), output)

    def restore(self, path: Path, passphrase: str, force: bool = False) -> None:
        if self.state() == "bound" and not force:
            raise AuthError("已有TOTP绑定；恢复请显式使用--force", 409)
        try:
            bundle = json.loads(Path(path).read_text(encoding="utf-8"))
            salt = base64.b64decode(bundle["salt"])
            payload = json.loads(Fernet(self._backup_key(passphrase, salt)).decrypt(
                bundle["ciphertext"].encode()).decode("utf-8"))
            key = payload["auth_key"].encode("ascii")
            state = payload["auth_state"]
            Fernet(key).decrypt(state["secret_encrypted"].encode())
        except (KeyError, ValueError, InvalidToken, json.JSONDecodeError) as exc:
            raise AuthError("备份口令错误或备份文件损坏", 400) from exc
        temp = self.key_path.with_suffix(".new")
        temp.write_bytes(key)
        os.chmod(temp, 0o600)
        os.replace(temp, self.key_path)
        self._atomic_json(self.state_path, state)
        self._remove(self.pending_path)
        self._remove(self.init_path)
        self.invalidate_all()

    def recover(self) -> tuple[str, int]:
        self._remove(self.state_path)
        self._remove(self.pending_path)
        self.invalidate_all()
        return self.initialize_token()

    def audit_tail(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT event, created_at, source_ip FROM audit ORDER BY id DESC LIMIT ?",
                (int(limit),)).fetchall()
        return [dict(row) for row in rows]


def datetime_from_timestamp(value: int) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)
