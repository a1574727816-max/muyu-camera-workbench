"""Offline dual-camera contract tests; never enter the service lifespan.

All media is empty or sparse, all state is temporary, and device/process
entry points fail if accidentally reached. Run: python -m pytest server/test_dual_camera.py
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pyotp
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import camera_web
import totp_auth
from media_guard import MediaGuard
from multi_camera import CameraHub, PassiveHealth
from totp_auth import AuthManager

NAMES = tuple(f"20261029T12000{i}-abcdef-000000.mkv" for i in range(6))
GB = 1_000_000_000


class Clock:
    now = 1_800_000_000

    def time(self):
        return self.now

    def __getattr__(self, name):
        return getattr(time, name)


def media_file(path, size=0, modified=100):
    """Mark NTFS files sparse before extending; never allocate GB of zeros."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        if size and os.name == "nt":
            import ctypes
            from ctypes import wintypes
            import msvcrt

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            control = kernel.DeviceIoControl
            control.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
            control.restype = wintypes.BOOL
            returned = wintypes.DWORD()
            if not control(msvcrt.get_osfhandle(handle.fileno()), 0x900C4,
                           None, 0, None, 0, ctypes.byref(returned), None):
                raise ctypes.WinError(ctypes.get_last_error())
            # Windows CRT truncate may explicitly write zeros even to a sparse
            # file. SetEndOfFile extends its logical length without writing data.
            seek = kernel.SetFilePointerEx
            seek.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                             ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
            seek.restype = wintypes.BOOL
            end = kernel.SetEndOfFile
            end.argtypes = [wintypes.HANDLE]
            end.restype = wintypes.BOOL
            native = msvcrt.get_osfhandle(handle.fileno())
            if not seek(native, size, None, 0) or not end(native):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            handle.truncate(size)
    os.utime(path, (modified, modified))
    return path


@pytest.fixture
def backend(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(camera_web, "DATA", tmp_path)
    monkeypatch.setattr(camera_web, "CONFIG", tmp_path / "config.json")
    monkeypatch.setattr(camera_web, "time", clock)
    monkeypatch.setattr(totp_auth, "time", clock)
    config = dict(camera_password="fixture-password", camera_host_key="ssh-ed25519 fixture-key",
                  expected_mac=camera_web.MAC, expected_uuid=camera_web.UUID,
                  mode="auto", manual_ip="192.168.1.10", recording=True,
                  segment_seconds=600, max_recording_bytes=camera_web.LIMIT,
                  wifi_desired=None)
    camera_web.atomic_json(camera_web.CONFIG, config)
    auth = AuthManager(tmp_path)
    token, _ = auth.initialize_token()
    binding = auth.begin_binding(token)
    secret = binding["secret"]
    auth.confirm_binding(token, pyotp.TOTP(secret).at(clock.now))
    auth_before = {p.name: p.read_bytes() for p in tmp_path.glob("auth*") if p.is_file()}
    forbidden = Mock(side_effect=AssertionError("offline test reached device/process entry point"))
    for name in ("ssh", "soap", "probes", "neighbours", "motor", "start_wifi", "run", "ptz_watchdog"):
        monkeypatch.setattr(camera_web.Manager, name, forbidden)
    monkeypatch.setattr(CameraHub, "run", forbidden)
    monkeypatch.setattr(camera_web.subprocess, "Popen", forbidden)
    monkeypatch.setattr(camera_web.subprocess, "run", forbidden)
    hub = CameraHub(tmp_path, camera_web.CONFIG, camera_web.Manager, auth, camera_web.atomic_json)
    env = SimpleNamespace(root=tmp_path, hub=hub, auth=auth, secret=secret, clock=clock,
                          config=config, auth_before=auth_before, forbidden=forbidden,
                          app=camera_web.build_app(hub))
    yield env
    forbidden.assert_not_called()
    assert hub.threads == []


@asynccontextmanager
async def client_for(env, *, login=True, csrf=True):
    # ASGITransport does not run lifespan: real Manager initialization is safe,
    # but no supervisors, ffmpeg processes, or device connections can start.
    transport = httpx.ASGITransport(app=env.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        if login:
            response = await client.post("/api/login", json={"code": pyotp.TOTP(env.secret).at(env.clock.now)})
            assert response.status_code == 200, response.text
            if csrf:
                client.headers["X-CSRF-Token"] = response.json()["csrf"]
        yield client


@pytest.mark.parametrize("path", ["/api/cameras", "/api/state", "/api/state?camera_id=cam1",
                                  "/api/live?camera_id=cam2", f"/api/recordings/{NAMES[0]}?camera_id=cam1"])
def test_session_required_before_camera_validation(backend, path):
    async def check():
        async with client_for(backend, login=False) as client:
            assert (await client.get(path)).status_code == 401
            assert (await client.post("/api/recording", json={"enabled": False})).status_code == 401
    asyncio.run(check())


@pytest.mark.parametrize("query, status", [("", 400), ("?camera_id=", 404),
    ("?camera_id=unknown", 404), ("?camera_id=cam1&camera_id=cam2", 400),
    ("?camera_id=cam1&camera_id=cam1", 400)])
def test_scoped_routes_require_exactly_one_known_id(backend, query, status):
    async def check():
        async with client_for(backend) as client:
            for path in ("/api/state", f"/api/recordings/{NAMES[0]}", f"/api/playback/{NAMES[0]}/status"):
                assert (await client.get(path + query)).status_code == status
            assert (await client.post("/api/recording" + query, json={"enabled": False})).status_code == status
            assert all(m.cfg["recording"] for m in backend.hub.managers.values())
    asyncio.run(check())


@pytest.mark.parametrize("csrf", [None, "incorrect"])
@pytest.mark.parametrize("cid", ["cam1", "cam2"])
def test_csrf_rejected_before_id_validation_and_mutation(backend, csrf, cid):
    async def check():
        async with client_for(backend, csrf=False) as client:
            if csrf is not None:
                client.headers["X-CSRF-Token"] = csrf
            raw = client.cookies["cam_session"]
            before = backend.auth.session(raw)
            backend.clock.now += 60
            for query in ("", f"?camera_id={cid}"):
                response = await client.post("/api/recording" + query, json={"enabled": False})
                assert response.status_code == 403
                assert "set-cookie" not in response.headers
            assert backend.auth.session(raw) == before
            assert all(m.cfg["recording"] for m in backend.hub.managers.values())
    asyncio.run(check())


def test_shared_session_listing_gets_do_not_slide_and_logout_is_global(backend):
    async def check():
        async with client_for(backend) as client:
            raw = client.cookies["cam_session"]
            before = backend.auth.session(raw)
            backend.clock.now += 60
            response = await client.get("/api/cameras")
            assert response.status_code == 200
            listing = response.json()
            cameras = listing["cameras"] if isinstance(listing, dict) else listing
            assert {c["id"] for c in cameras} == {"cam1", "cam2"}
            assert "fixture-password" not in response.text
            for cid in ("cam1", "cam2"):
                response = await client.get(f"/api/state?camera_id={cid}")
                assert response.status_code == 200
                assert response.json()["camera_id"] == cid
                assert response.json()["csrf"] == before["csrf"]
                assert "set-cookie" not in response.headers
            assert backend.auth.session(raw) == before
            assert (await client.post("/api/logout", json={})).status_code == 200
            assert backend.auth.session(raw) is None
            for cid in ("cam1", "cam2"):
                assert (await client.get(f"/api/state?camera_id={cid}")).status_code == 401
    asyncio.run(check())


def test_concurrent_state_lists_and_downloads_are_scoped_including_legacy(backend):
    first, second = backend.hub.managers.values()
    media_file(first.rec_dir / NAMES[0])
    media_file(second.rec_dir / NAMES[1])
    legacy = media_file(backend.root / "recordings" / NAMES[2])
    assert first.recording_path(NAMES[2]) == legacy
    assert legacy not in second.recording_files()

    async def check():
        async with client_for(backend) as client:
            ids = ["cam1", "cam2"] * 8
            responses = await asyncio.gather(*(client.get(f"/api/state?camera_id={cid}") for cid in ids))
            for cid, response in zip(ids, responses):
                assert response.status_code == 200
                state = response.json()
                assert state["camera_id"] == cid
                assert {r["name"] for r in state["recordings"]} == ({NAMES[0], NAMES[2]} if cid == "cam1" else {NAMES[1]})
            for name, owner in ((NAMES[0], "cam1"), (NAMES[1], "cam2"), (NAMES[2], "cam1")):
                for cid in ("cam1", "cam2"):
                    response = await client.get(f"/api/recordings/{name}?camera_id={cid}")
                    assert response.status_code == (200 if cid == owner else 404)
                    if response.status_code == 200:
                        assert response.content == b""
                        assert "set-cookie" not in response.headers
    asyncio.run(check())


@pytest.mark.parametrize("path, body", [("/api/ptz", {"x": 1, "y": 0}),
    ("/api/wifi", {"ssid": "offline", "password": "unused-password"})])
def test_cam2_control_routes_reject_before_hardware(backend, path, body):
    second = backend.hub.managers["cam2"]
    assert second.capabilities == dict(ptz=False, wifi=False, ssh_recovery=False)
    assert isinstance(second.media_guard, PassiveHealth)
    assert isinstance(backend.hub.managers["cam1"].media_guard, MediaGuard)

    async def check():
        async with client_for(backend) as client:
            raw = client.cookies["cam_session"]
            before = backend.auth.session(raw)
            backend.clock.now += 60
            response = await client.post(path + "?camera_id=cam2", json=body)
            assert response.status_code == 409
            assert "set-cookie" not in response.headers
            assert backend.auth.session(raw) == before
    asyncio.run(check())


@pytest.mark.parametrize("cid", ["cam1", "cam2"])
def test_recording_changes_only_selected_camera_and_slides_shared_session(backend, cid):
    async def check():
        async with client_for(backend) as client:
            raw = client.cookies["cam_session"]
            before = backend.auth.session(raw)["expires_at"]
            backend.clock.now += 60
            response = await client.post(f"/api/recording?camera_id={cid}", json={"enabled": False})
            assert response.status_code == 200
            assert "set-cookie" in response.headers
            assert backend.auth.session(raw)["expires_at"] > before
            saved = json.loads(backend.hub.config_path.read_text(encoding="utf-8"))
            for other, manager in backend.hub.managers.items():
                assert manager.cfg["recording"] is (other != cid)
                assert saved["cameras"][other]["recording"] is (other != cid)
    asyncio.run(check())


def test_concurrent_recording_posts_preserve_both_changes(backend):
    async def check():
        async with client_for(backend) as client:
            responses = await asyncio.gather(*(client.post(f"/api/recording?camera_id={cid}",
                json={"enabled": False}) for cid in ("cam1", "cam2")))
            assert [r.status_code for r in responses] == [200, 200]
            saved = json.loads(backend.hub.config_path.read_text(encoding="utf-8"))
            assert all(not m.cfg["recording"] for m in backend.hub.managers.values())
            assert all(not c["recording"] for c in saved["cameras"].values())
    asyncio.run(check())


def test_migration_preserves_credentials_legacy_and_auth_files(backend):
    hub = backend.hub
    saved = json.loads(hub.config_path.read_text(encoding="utf-8"))
    assert set(saved["cameras"]) == {"cam1", "cam2"}
    for key, value in backend.config.items():
        assert saved["cameras"]["cam1"][key] == value
    assert "camera_password" not in saved["cameras"]["cam2"]
    assert "camera_host_key" not in saved["cameras"]["cam2"]
    assert all(m.auth is backend.auth for m in hub.managers.values())
    assert backend.auth_before == {p.name: p.read_bytes() for p in backend.root.glob("auth*") if p.is_file()}
    before = hub.config_path.read_bytes()
    restarted = CameraHub(backend.root, hub.config_path, camera_web.Manager, backend.auth, camera_web.atomic_json)
    assert hub.config_path.read_bytes() == before
    assert all(m.auth is backend.auth for m in restarted.managers.values())
    assert backend.auth_before == {p.name: p.read_bytes() for p in backend.root.glob("auth*") if p.is_file()}


def test_concurrent_manager_saves_serialize_atomic_writer(backend):
    hub = backend.hub
    barrier = threading.Barrier(2)
    writer_lock = threading.Lock()
    activity = dict(active=0, peak=0, calls=0)

    def writer(path, config):
        with writer_lock:
            activity["active"] += 1
            activity["peak"] = max(activity["peak"], activity["active"])
            activity["calls"] += 1
        try:
            time.sleep(.002)  # Give the other save a chance to contend for the lock.
            camera_web.atomic_json(path, config)
        finally:
            with writer_lock:
                activity["active"] -= 1

    hub.writer = writer

    def save(cid):
        manager = hub.managers[cid]
        barrier.wait(timeout=5)
        for i in range(8):
            with manager.lock:
                manager.cfg["name"] = f"{cid}-{i}"
                manager.save()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(save, cid) for cid in ("cam1", "cam2")]
        for future in futures:
            future.result(timeout=10)
    assert activity == dict(active=0, peak=1, calls=16)
    saved = json.loads(hub.config_path.read_text(encoding="utf-8"))
    assert {cid: c["name"] for cid, c in saved["cameras"].items()} == {"cam1": "cam1-7", "cam2": "cam2-7"}
    assert not hub.config_path.with_suffix(".new").exists()


def test_shared_quota_prunes_global_oldest_including_legacy_and_preserves_writers_parts_pins(backend):
    hub = backend.hub
    first, second = hub.managers.values()
    legacy = media_file(backend.root / "recordings" / NAMES[0], 2 * GB, 10)
    oldest = media_file(second.rec_dir / NAMES[1], 2 * GB, 20)
    newer = media_file(first.rec_dir / NAMES[2], 2 * GB, 30)
    pinned = media_file(second.rec_dir / NAMES[3], GB, 1)
    hub.pin(pinned)
    active = []
    parts = []
    for index, manager in enumerate((first, second)):
        manager.rec_prefix = f"20261029T13000{index}-aaaaaa-"
        manager.rec = SimpleNamespace(poll=lambda: None)
        active.append(media_file(manager.rec_dir / (manager.rec_prefix + "000001.mkv"), 12 * GB, 2))
        parts.append(media_file(manager.play_dir / f"conversion-{index}.part.mp4", 250_000_000, 3))
    assert hub.usage() == (31_500_000_000, 500_000_000)
    # Adding 3GB requires removing the two globally oldest eligible clips,
    # first the cam1 legacy file and then the older cam2 recording.
    extra = media_file(second.rec_dir / NAMES[4], 3 * GB, 40)
    assert hub.usage()[0] == 34_500_000_000
    total, removed = hub.prune()
    assert removed == [str(legacy), str(oldest)]
    assert not legacy.exists() and not oldest.exists()
    assert all(p.exists() for p in [newer, pinned, extra, *active, *parts])
    assert total == hub.usage()[0] == 30_500_000_000
    assert total <= camera_web.LIMIT - camera_web.RESERVE
    hub.unpin(pinned)
    hub.limit = total - GB + camera_web.RESERVE
    _, removed = hub.prune()
    assert removed == [str(pinned)]


def test_prune_deletes_closed_segments_from_running_writer(backend):
    hub = backend.hub
    active, closed = [], []
    for index, manager in enumerate(hub.managers.values()):
        manager.rec_prefix = f"20261029T14000{index}-bbbbbb-"
        manager.rec = SimpleNamespace(poll=lambda: None)
        closed.append(media_file(manager.rec_dir / (manager.rec_prefix + "000000.mkv"), 2 * GB, 10 + index))
        active.append(media_file(manager.rec_dir / (manager.rec_prefix + "000001.mkv"), 14 * GB, 20 + index))
    total, removed = hub.prune()
    assert total <= camera_web.LIMIT - camera_web.RESERVE
    assert removed == [str(closed[0])]
    assert all(p.exists() for p in active)
    assert closed[1].exists()


def test_pins_are_reference_counted_across_concurrent_pruners(backend):
    hub = backend.hub
    first, second = hub.managers.values()
    pinned = media_file(first.rec_dir / NAMES[0], 3 * GB, 1)
    old = media_file(second.rec_dir / NAMES[1], 3 * GB, 2)
    kept = media_file(first.rec_dir / NAMES[2], 28 * GB, 3)
    hub.pin(pinned)
    hub.pin(pinned)
    hub.unpin(pinned)
    barrier = threading.Barrier(2)

    def prune():
        barrier.wait(timeout=5)
        return hub.prune()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(prune) for _ in range(2)]
        results = [f.result(timeout=10) for f in futures]
    assert [p for _, removed in results for p in removed] == [str(old)]
    assert pinned.exists() and kept.exists()
    assert hub.usage()[0] == 31 * GB
    hub.unpin(pinned)
    hub.limit = 29 * GB + camera_web.RESERVE
    assert hub.prune()[1] == [str(pinned)]
    assert not hub.pins
