"""Recovery decisions use isolated observations, never a real camera connection."""
import concurrent.futures
from pathlib import Path
import tempfile
import threading
import unittest

from media_guard import CORE_PATTERN, HELPER_MD5, MediaGuard, parse_snapshot


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 10000
        self.mono = 0
        self.commands = []
        self.events = []
        self.restarts = 0
        self.raw = self.snapshot()
        self.guard = self.make()

    def snapshot(self, *, state='D', frames=0, rtsp=0, uptime=1000, count=1):
        return (f'UPTIME={uptime}\nCOUNT={count}\nPID=1467\nSTATE={state}\n'
                f'FRAMES={frames}\nRTSP={rtsp}\nHELPER={HELPER_MD5}\nPATTERN={CORE_PATTERN}\nCORE=\n').encode()

    def ssh(self, ip, command, **kwargs):
        self.commands.append(command)
        if 'MEDIA_RECOVERY_SCHEDULED' in command:
            return b'MEDIA_RECOVERY_SCHEDULED\n'
        return self.raw

    def restart(self):
        self.restarts += 1

    def make(self):
        return MediaGuard(Path(self.tmp.name), self.ssh, self.events.append, self.restart,
                          threading.Event(), clock=lambda: self.now, monotonic=lambda: self.mono)

    def tick(self, at, progress=0, wanted=True):
        self.mono = at
        self.guard.tick('192.168.1.10', wanted, progress)

    def reboot_count(self):
        return sum('MEDIA_RECOVERY_SCHEDULED' in c for c in self.commands)

    def test_exact_observed_failure_requires_two_samples_and_saves_evidence(self):
        self.tick(0)
        self.tick(89)
        self.assertEqual(self.reboot_count(), 0)
        self.tick(100)
        self.assertEqual(self.reboot_count(), 0)
        self.assertEqual(self.restarts, 1)
        self.tick(120)
        self.assertEqual(self.reboot_count(), 1)
        self.assertTrue(list(Path(self.tmp.name, 'media-incidents').glob('*.json')))
        self.assertTrue(Path(self.tmp.name, 'media-recovery.json').exists())

    def test_healthy_progress_and_paused_recording_never_reboot(self):
        for at in range(0, 1000, 20):
            self.tick(at, progress=at)
        self.assertEqual(self.reboot_count(), 0)
        for at in range(1000, 1500, 20):
            self.tick(at, progress=1000, wanted=False)
        self.assertEqual(self.reboot_count(), 0)

    def test_network_exception_cannot_confirm_device_failure(self):
        self.tick(0)
        self.tick(100)
        def unavailable(*args, **kwargs):
            raise OSError('network unavailable')
        self.guard.ssh = unavailable
        with self.assertRaises(OSError):
            self.tick(120)
        self.assertEqual(self.reboot_count(), 0)

    def test_healthy_encoder_only_requests_server_reconnect(self):
        self.raw = self.snapshot(state='S', frames=1234, rtsp=1)
        for at in (0, 100, 120, 140):
            self.tick(at)
        self.assertEqual(self.reboot_count(), 0)
        self.assertEqual(self.restarts, 1)

    def test_boot_grace_and_ambiguous_processes_never_reboot(self):
        for raw in (self.snapshot(uptime=170), self.snapshot(count=2)):
            self.guard = self.make()
            self.raw = raw
            for at in (0, 100, 120):
                self.tick(at)
        self.assertEqual(self.reboot_count(), 0)

    def test_unknown_encoder_counter_does_not_reboot(self):
        self.raw = self.snapshot().replace(b'FRAMES=0', b'FRAMES=')
        for at in (0, 100, 120):
            self.tick(at)
        self.assertEqual(self.reboot_count(), 0)

    def test_recovery_limit_survives_new_guard_and_clock_rollback(self):
        snapshot = parse_snapshot(self.raw)
        self.assertTrue(self.guard.reserve_recovery('192.168.1.10', snapshot))
        self.assertFalse(self.make().reserve_recovery('192.168.1.10', snapshot))
        self.now -= 100
        self.assertFalse(self.make().reserve_recovery('192.168.1.10', snapshot))
        self.now += 2000
        self.assertTrue(self.make().reserve_recovery('192.168.1.10', snapshot))
        self.now += 2000
        self.assertTrue(self.make().reserve_recovery('192.168.1.10', snapshot))
        self.now += 2000
        self.assertFalse(self.make().reserve_recovery('192.168.1.10', snapshot))

    def test_concurrent_reservation_is_atomic(self):
        snapshot = parse_snapshot(self.raw)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.make().reserve_recovery('192.168.1.10', snapshot), range(12)))
        self.assertEqual(sum(results), 1)

    def test_one_transient_sample_followed_by_progress_does_not_reboot(self):
        self.tick(0)
        self.tick(100)
        self.tick(120, progress=1)
        self.tick(140, progress=2)
        self.assertEqual(self.reboot_count(), 0)

    def test_existing_other_core_handler_is_not_overwritten(self):
        self.raw = self.snapshot().replace(CORE_PATTERN.encode(), b'|/other/handler')
        with self.assertRaises(RuntimeError):
            self.tick(0)
        self.assertFalse(any('cat > /tmp/localcam-core-collect' in c for c in self.commands))

    def test_resume_from_long_idle_has_a_fresh_stall_window(self):
        self.tick(0, wanted=False)
        self.tick(1000, wanted=False)
        self.tick(2000, wanted=True)
        self.assertEqual(self.restarts, 0)
        self.tick(2020, progress=1)
        self.assertEqual(self.reboot_count(), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
