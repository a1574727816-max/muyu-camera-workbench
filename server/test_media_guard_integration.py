"""Check recorder retry cadence without starting ffmpeg or contacting a device."""
import threading
from types import SimpleNamespace
from unittest.mock import patch

import camera_web


def test_refused_stream_does_not_spawn_ffmpeg_every_second(tmp_path):
    m = camera_web.Manager.__new__(camera_web.Manager)
    m.cfg = dict(recording=True, max_recording_bytes=camera_web.LIMIT, segment_seconds=600)
    m.ip = m.rec_ip = '192.168.1.10'
    m.rec = None
    m.rec_dir = tmp_path
    m.lock = threading.RLock()
    m.record_retry_at = m.record_failures = m.record_started = 0
    m.active_name = lambda: None
    m.cache_tick = lambda: 0
    m.event = lambda message: None
    fake = SimpleNamespace(poll=lambda: 1, stderr=[])
    with patch.object(camera_web.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1000000, f_frsize=4096), create=True):
        with patch.object(camera_web.subprocess, 'Popen', return_value=fake) as spawn:
            for now in range(61):
                with patch.object(camera_web.time, 'monotonic', return_value=now):
                    m.recorder_tick()
            assert 2 <= spawn.call_count <= 6
            assert m.record_error
