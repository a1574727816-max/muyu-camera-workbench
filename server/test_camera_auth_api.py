import asyncio
import tempfile
import threading
from pathlib import Path

import httpx
import pyotp
import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import camera_web
from totp_auth import AuthManager


class FakeManager:
    def __init__(self, data):
        self.auth = AuthManager(Path(data), absolute_ttl=None)
        self.stop = threading.Event()
        self.ip = None
        self.wakeup = threading.Event()
        self.cfg = {"camera_password": "unused"}

    def run(self):
        self.stop.wait(2)

    def ptz_watchdog(self):
        self.stop.wait(2)

    def state(self, offset=0):
        return {}


def bind(auth):
    token, _ = auth.initialize_token()
    pending = auth.begin_binding(token)
    auth.confirm_binding(token, pyotp.TOTP(pending["secret"]).now())
    return pending["secret"]


def test_api_totp_only_and_sliding_policy():
    async def run():
        with tempfile.TemporaryDirectory() as temp:
            manager = FakeManager(temp)
            secret = bind(manager.auth)
            app = camera_web.build_app(manager)
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                assert (await client.get("/api/state")).status_code == 401
                assert (await client.get("/api/live")).status_code == 401
                assert (await client.post("/api/login", json={"username": "root", "password": "old"})).status_code == 400
                login = await client.post("/api/login", json={"code": pyotp.TOTP(secret).now()})
                assert login.status_code == 200
                assert "cam_session=" in login.headers["set-cookie"]
                raw = client.cookies.get("cam_session")
                before = manager.auth.session(raw)["expires_at"]
                poll = await client.get("/api/state")
                assert poll.status_code == 200
                client.headers["X-CSRF-Token"] = poll.json()["csrf"]
                assert "set-cookie" not in poll.headers
                assert manager.auth.session(raw)["expires_at"] == before
                action = await client.post("/api/discover", json={})
                assert action.status_code == 200
                assert "set-cookie" in action.headers
                assert manager.auth.session(raw)["expires_at"] >= before
                await client.post("/api/logout", json={})
                assert manager.auth.session(raw) is None
                assert (await client.get("/api/state")).status_code == 401
    asyncio.run(run())
