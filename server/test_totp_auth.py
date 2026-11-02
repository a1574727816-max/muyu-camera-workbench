import json
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pyotp
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from totp_auth import AuthError, AuthManager, SESSION_TTL


def bind(auth):
    token, _ = auth.initialize_token()
    payload = auth.begin_binding(token)
    assert payload["otpauth_uri"].startswith("otpauth://totp/")
    assert "<svg" in payload["qr_svg"]
    auth.confirm_binding(token, pyotp.TOTP(payload["secret"]).now())
    return payload["secret"]


def test_totp_binding_login_replay_and_sliding_session():
    with tempfile.TemporaryDirectory() as temp:
        auth = AuthManager(Path(temp), absolute_ttl=None)
        secret = bind(auth)
        fixed = 1_800_000_000
        with patch("totp_auth.time.time", return_value=fixed):
            token, csrf, expires = auth.login(pyotp.TOTP(secret).at(fixed), "127.0.0.1")
            assert csrf and expires == fixed + SESSION_TTL
            row = auth.session(token)
            assert row["expires_at"] == expires
            assert not auth.should_slide("GET", "/api/state")
            assert not auth.should_slide("GET", "/api/live")
            assert not auth.should_slide("GET", "/api/play/x/stream")
            assert auth.should_slide("POST", "/api/ptz")
            assert auth.should_slide("POST", "/api/playback/x/prepare")
            assert auth.should_slide("POST", "/api/auth/rotate/start")
            assert auth.should_slide("POST", "/api/auth/rotate/confirm")
            assert auth.should_slide("POST", "/api/device")
            assert auth.should_slide("POST", "/api/recording")
            assert auth.should_slide("POST", "/api/wifi")
            assert not auth.should_slide("POST", "/api/login")
            assert not auth.should_slide("POST", "/api/logout")
            assert not auth.should_slide("GET", "/api/auth/status")
            auth.slide(token)
            assert auth.session(token)["expires_at"] == fixed + SESSION_TTL
            with pytest.raises(AuthError):
                auth.login(pyotp.TOTP(secret).now(), "127.0.0.1")
        with patch("totp_auth.time.time", return_value=fixed + SESSION_TTL - 1):
            assert auth.session(token)
        with patch("totp_auth.time.time", return_value=fixed + SESSION_TTL + 1):
            assert auth.session(token) is None


def test_rotation_invalidates_sessions_and_old_secret():
    with tempfile.TemporaryDirectory() as temp:
        auth = AuthManager(Path(temp), absolute_ttl=None)
        old_secret = bind(auth)
        token, _, _ = auth.login(pyotp.TOTP(old_secret).now(), "127.0.0.1")
        pending = auth.rotate_start(pyotp.TOTP(old_secret).now(), token)
        new_secret = pending["secret"]
        auth.rotate_confirm(pyotp.TOTP(new_secret).now(), token)
        assert auth.session(token) is None
        new_token, _, _ = auth.login(pyotp.TOTP(new_secret).now(), "127.0.0.1")
        assert auth.session(new_token)


def test_backup_restore_does_not_overwrite_business_data():
    with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
        source = AuthManager(Path(left), absolute_ttl=None)
        secret = bind(source)
        business = Path(right) / "business.txt"
        business.write_text("keep", encoding="utf-8")
        restored = AuthManager(Path(right), absolute_ttl=None)
        backup = Path(left) / "totp.backup"
        source.backup(backup, "backup-passphrase")
        restored.restore(backup, "backup-passphrase", force=True)
        assert business.read_text(encoding="utf-8") == "keep"
        token, _, _ = restored.login(pyotp.TOTP(secret).now(), "127.0.0.1")
        assert restored.session(token)


def test_restart_persists_session_and_absolute_limit_caps_sliding():
    with tempfile.TemporaryDirectory() as temp:
        absolute = 4 * SESSION_TTL
        auth = AuthManager(Path(temp), absolute_ttl=absolute)
        secret = bind(auth)
        fixed = 1_800_000_000
        with patch("totp_auth.time.time", return_value=fixed):
            token, _, _ = auth.login(pyotp.TOTP(secret).at(fixed), "127.0.0.1")
        restarted = AuthManager(Path(temp), absolute_ttl=absolute)
        assert restarted.session(token)
        with patch("totp_auth.time.time", return_value=fixed + 47 * 60 * 60):
            assert restarted.slide(token)
        with patch("totp_auth.time.time", return_value=fixed + 3 * 24 * 60 * 60):
            assert restarted.slide(token)
        with patch("totp_auth.time.time", return_value=fixed + 4 * 24 * 60 * 60):
            assert restarted.slide(token)
        with patch("totp_auth.time.time", return_value=fixed + 5 * 24 * 60 * 60):
            assert restarted.slide(token)
        with patch("totp_auth.time.time", return_value=fixed + 6 * 24 * 60 * 60):
            row = restarted.slide(token)
            assert row["expires_at"] == fixed + absolute
        with patch("totp_auth.time.time", return_value=fixed + absolute + 1):
            assert restarted.session(token) is None


def test_unauthorized_binding_and_rate_limit():
    with tempfile.TemporaryDirectory() as temp:
        auth = AuthManager(Path(temp), absolute_ttl=None)
        with pytest.raises(AuthError) as exc:
            auth.begin_binding("wrong")
        assert exc.value.status == 403
        secret = bind(auth)
        code = pyotp.TOTP(secret).now()
        token, _, _ = auth.login(code, "127.0.0.1")
        assert token
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: _bad(auth), range(12)))
        assert any(item in ("401", "429") for item in results)


def _bad(auth):
    try:
        auth.login("000000", "192.0.2.1")
    except AuthError as exc:
        return str(exc.status)
    return "accepted"
