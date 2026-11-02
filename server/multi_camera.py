"""Two independent camera workers, shared authentication and storage budget."""
import json
import os
from pathlib import Path
import shutil
import threading
import time

IDS = ('cam1', 'cam2')
CAPABILITIES = {
    'cam1': dict(ptz=True, wifi=True, ssh_recovery=True),
    'cam2': dict(ptz=False, wifi=False, ssh_recovery=False),
}


class PassiveHealth:
    def status(self):
        return {'state': 'rtsp-only', 'message': ''}


class CameraHub:
    def __init__(self, data, config, factory, auth, writer):
        self.data, self.config_path, self.writer = Path(data), Path(config), writer
        self.auth, self.stop = auth, threading.Event()
        self.config_lock = threading.RLock()
        self.storage_lock = threading.RLock()
        self.play_stream_slots = threading.BoundedSemaphore(2)
        self.cache_slot = threading.Semaphore(1)
        self.pins = {}
        cfg = json.loads(self.config_path.read_text())
        if 'cameras' not in cfg:
            original = dict(cfg)
            original.update(name='摄像头一', onvif_port=8899, video_codec='H.265',
                            video_resolution='1920×1080')
            second = dict(name='摄像头二', expected_mac=os.environ.get('CAM2_EXPECTED_MAC', '02:00:00:00:00:02'),
                          expected_uuid=os.environ.get('CAM2_EXPECTED_UUID', '00000000-0000-4000-8000-000000000002'),
                          manual_ip=os.environ.get('CAM2_CAMERA_IP', '192.168.1.11'), mode='auto', recording=True,
                          segment_seconds=600, max_recording_bytes=32_000_000_000,
                          wifi_desired=None, onvif_port=2020, video_codec='H.264',
                          video_resolution='1280×720')
            cfg.update(schema_version=2, cameras={'cam1': original, 'cam2': second})
            # Retain original top-level fields for a reversible old-code rollback.
            self.writer(self.config_path, cfg)
        if set(cfg['cameras']) != set(IDS):
            raise ValueError('摄像头配置ID不完整')
        self.cfg = cfg
        self.limit = int(cfg.get('max_recording_bytes', 32_000_000_000))
        self.min_free_bytes = max(256 * 1024 * 1024,
                                  int(os.environ.get('CAM_DISK_FREE_BYTES', str(2 * 1024**3))))
        self.managers = {}
        for cid in IDS:
            camera = cfg['cameras'][cid]
            camera['max_recording_bytes'] = self.limit
            camera['segment_seconds'] = 600
            self.managers[cid] = factory(camera, self, cid)
        self.threads = []

    def save(self):
        with self.config_lock:
            self.writer(self.config_path, self.cfg)

    def cameras(self):
        return [dict(id=cid, name=m.cfg['name'], capabilities=dict(m.capabilities),
                     ip=m.ip, online=bool(m.ip),
                     recording=bool(m.rec and m.rec.poll() is None),
                     recording_enabled=m.cfg['recording'])
                for cid, m in self.managers.items()]

    def run(self):
        for m in self.managers.values():
            for target in ([m.run, m.ptz_watchdog] if m.capabilities['ptz'] else [m.run]):
                t = threading.Thread(target=target, daemon=True)
                t.start()
                self.threads.append(t)
        self.stop.wait()
        for m in self.managers.values():
            m.stop.set()
        for t in self.threads:
            t.join(10)

    def ptz_watchdog(self):
        # Each capable camera owns its own watchdog.
        self.stop.wait()

    def shutdown_controls(self):
        for m in self.managers.values():
            if m.capabilities['ptz'] and m.ip:
                try:
                    m.ptz(0, 0)
                except Exception:
                    pass

    def select_preview(self, manager):
        # Per-stream interest, never a global selected camera. Different tabs
        # may view different devices; each device shares one preview encoder.
        with manager.preview_lock:
            manager.preview_clients += 1
            manager.preview_seen = time.time()

    def release_preview(self, manager):
        with manager.preview_lock:
            manager.preview_clients = max(0, manager.preview_clients - 1)
            if not manager.preview_clients:
                manager.preview_seen = 0

    def pin(self, path):
        with self.storage_lock:
            key = str(path)
            self.pins[key] = self.pins.get(key, 0) + 1

    def unpin(self, path):
        with self.storage_lock:
            key = str(path)
            if self.pins.get(key, 0) > 1:
                self.pins[key] -= 1
            else:
                self.pins.pop(key, None)

    def prune(self):
        with self.storage_lock:
            recordings, caches, protected = [], [], set(self.pins)
            for m in self.managers.values():
                recordings.extend(m.recording_files())
                caches.extend(m.cache_files())
                if m.rec and m.rec.poll() is None:
                    active = m._active_name()
                    if active:
                        protected.add(str(m.rec_dir / active))
                protected.update(str(p) for p in m.play_dir.glob('*.part.mp4'))
            def size(p):
                try:
                    return p.stat().st_size
                except FileNotFoundError:
                    return 0
            total = sum(size(p) for p in recordings + caches)
            target = self.limit - 256 * 1024 * 1024
            # A quota bounds our files, but unrelated services can fill the
            # same filesystem. Reclaim only our eligible files with headroom.
            free_target = (self.min_free_bytes + 256 * 1024 * 1024
                           if shutil.disk_usage(self.data).free < self.min_free_bytes else 0)
            def needs_space():
                return (total > target or
                        bool(free_target and shutil.disk_usage(self.data).free < free_target))
            removed = []
            # Cached copies are expendable before original recordings.
            budget = sum(size(p) for p in caches)
            cache_order = sorted(caches, key=lambda p: p.stat().st_mtime)
            for p in cache_order:
                if str(p) in protected or p.name.endswith('.part.mp4'):
                    continue
                if budget <= 512 * 1024 * 1024 and not needs_space():
                    break
                amount = size(p)
                p.unlink(missing_ok=True)
                budget -= amount
                total -= amount
            for p in sorted(recordings, key=lambda p: p.stat().st_mtime):
                if not needs_space():
                    break
                if str(p) in protected:
                    continue
                # A segment may roll over after enumeration. Recheck immediately
                # before deletion; completed files are never reopened by segment.
                if any(m.rec and m.rec.poll() is None and p.parent == m.rec_dir
                       and p.name == m._active_name() for m in self.managers.values()):
                    continue
                amount = size(p)
                p.unlink(missing_ok=True)
                total -= amount
                removed.append(str(p))
            return total, removed

    def usage(self):
        with self.storage_lock:
            recordings = caches = 0
            for m in self.managers.values():
                for p in m.recording_files():
                    try:
                        recordings += p.stat().st_size
                    except FileNotFoundError:
                        pass
                for p in m.cache_files():
                    try:
                        caches += p.stat().st_size
                    except FileNotFoundError:
                        pass
            return recordings + caches, caches
