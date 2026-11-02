"""Bounded camera crash capture and conservative recovery over pinned SSH.

No camera Flash writes. The SSH callback verifies the existing device key.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time


CORE_HELPER = r'''#!/bin/sh
BB=/bin/busybox
umask 077
ulimit -t 20
ulimit -f 6144
case "$1:$2:$3" in *[!0-9:]*|'') exit 1;; esac
case "$4" in
    cet|cet_main) dest=/tmp/localcam-crash;;
    cet-core-probe) [ -f /tmp/localcam-core-test.enabled ] || exit 1; dest=/tmp/localcam-core-test;;
    *) exec $BB cat >/dev/null;;
esac
free=$($BB df -k /tmp | $BB awk 'NR==2 {print $4}')
[ "${free:-0}" -gt 4096 ] || exit 1
$BB rm -f "$dest.meta" "$dest.gz.part"
if $BB nice -n 19 $BB gzip -c > "$dest.gz.part"; then
    $BB mv -f "$dest.gz.part" "$dest.gz" || exit 1
    echo "$1 $2 $3 $4" > "$dest.meta.new"
    $BB mv -f "$dest.meta.new" "$dest.meta"
else
    $BB rm -f "$dest.gz.part"
    exit 1
fi
'''
CORE_PATTERN = '|/tmp/localcam-core-collect %p %s %t %e'
HELPER_MD5 = hashlib.md5(CORE_HELPER.encode()).hexdigest()

SNAPSHOT = r'''
BB=/bin/busybox
echo "UPTIME=$($BB awk '{print int($1)}' /proc/uptime)"
p=$($BB pidof cet)
set -- $p
echo "COUNT=$#"
if [ "$#" = 1 ]; then
    echo "PID=$1"
    echo "STATE=$($BB awk '{print $3}' /proc/$1/stat)"
fi
echo "FRAMES=$($BB awk '$1=="0" && $2=="H265" {print $7; exit}' /proc/mi_modules/mi_venc/mi_venc0)"
echo "RTSP=$($BB netstat -lnt | $BB awk '$4 ~ /:554$/ && $6=="LISTEN" {found=1} END {print found+0}')"
echo "HELPER=$($BB md5sum /tmp/localcam-core-collect 2>/dev/null | $BB awk '{print $1}')"
echo "PATTERN=$($BB cat /proc/sys/kernel/core_pattern)"
echo "CORE=$($BB cat /tmp/localcam-crash.meta 2>/dev/null)"
'''


def parse_snapshot(raw):
    fields = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
    out = {'state': fields.get('STATE', ''), 'helper': fields.get('HELPER', ''),
           'pattern': fields.get('PATTERN', ''), 'core': fields.get('CORE', '')}
    for source, target in [('UPTIME', 'uptime'), ('COUNT', 'count'), ('PID', 'pid'),
                           ('FRAMES', 'frames'), ('RTSP', 'rtsp')]:
        value = fields.get(source, '')
        out[target] = int(value) if value.isdigit() else None
    return out


@contextmanager
def exclusive(path):
    # Production is Linux; flock is released by the OS even after a hard exit.
    import fcntl
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class MediaGuard:
    def __init__(self, data, ssh, event, restart, stop, *, clock=time.time,
                 monotonic=time.monotonic, delay=90, cooldown=1800, daily_limit=3):
        self.data = Path(data)
        self.ssh, self.event, self.restart, self.stop = ssh, event, restart, stop
        self.clock, self.monotonic = clock, monotonic
        self.delay = max(60, delay)
        self.cooldown, self.daily_limit = max(900, cooldown), max(1, daily_limit)
        self.lock = threading.Lock()
        self.health = {'state': 'starting', 'message': ''}
        self.ip = None
        self.since = 0
        self.progress = None
        self.progress_at = 0
        self.next_snapshot = 0
        self.next_install = 0
        self.previous = None
        self.server_retry = False
        self.last_core = None
        self.wanted = False

    def status(self):
        with self.lock:
            return dict(self.health)

    def update(self, state, message='', **details):
        with self.lock:
            self.health = dict(state=state, message=message, **details)

    def install_collector(self, ip, snapshot):
        if snapshot['pattern'] not in ('core', CORE_PATTERN):
            raise RuntimeError('已有其他崩溃处理器，保留现有配置')
        if snapshot['helper'] == HELPER_MD5 and snapshot['pattern'] == CORE_PATTERN:
            return
        command = r'''
umask 077
/bin/busybox cat > /tmp/localcam-core-collect.new || exit 1
/bin/busybox chmod 700 /tmp/localcam-core-collect.new || exit 1
/bin/busybox mv -f /tmp/localcam-core-collect.new /tmp/localcam-core-collect || exit 1
echo 1 > /proc/sys/kernel/core_pipe_limit || exit 1
echo '|/tmp/localcam-core-collect %p %s %t %e' > /proc/sys/kernel/core_pattern || exit 1
/bin/busybox md5sum /tmp/localcam-core-collect
'''
        reply = self.ssh(ip, command, data=CORE_HELPER.encode())
        if reply.split()[0].decode() != HELPER_MD5:
            raise RuntimeError('崩溃取证脚本校验失败')

    def capture(self, ip, snapshot):
        incident = self.data / 'media-incidents'
        incident.mkdir(mode=0o700, exist_ok=True)
        name = str(int(self.clock())) + '-' + secrets.token_hex(3)
        evidence = incident / (name + '.json')
        evidence.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n')
        os.chmod(evidence, 0o600)
        core_id = snapshot['core']
        if core_id and core_id != self.last_core:
            raw = self.ssh(ip, '/bin/busybox cat /tmp/localcam-crash.gz',
                           timeout=35, max_bytes=3 * 1024 * 1024)
            after = self.ssh(ip, '/bin/busybox cat /tmp/localcam-crash.meta').decode().strip()
            if after != core_id or raw[:2] != b'\x1f\x8b':
                raise RuntimeError('崩溃转储仍在更新，稍后重试')
            path = incident / (name + '.core.gz')
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            self.last_core = core_id
            self.event('已保存摄像头媒体崩溃转储，供继续定位')
        # Only guard-owned files, at most eight snapshots/cores; no recordings.
        for suffix in ('.json', '.core.gz'):
            files = sorted(incident.glob('*' + suffix), key=lambda p: p.stat().st_mtime)
            for path in files[:-8]:
                path.unlink()

    def reserve_recovery(self, ip, snapshot):
        with exclusive(self.data / 'media-recovery.lock'):
            path = self.data / 'media-recovery.json'
            history = json.loads(path.read_text()) if path.exists() else {'attempts': []}
            now = self.clock()
            # Future entries also enforce cooldown if the server clock moves back.
            attempts = [entry for entry in history['attempts'] if now - entry['at'] < 86400]
            if attempts and now - attempts[-1]['at'] < self.cooldown:
                return False
            if len(attempts) >= self.daily_limit:
                return False
            attempts.append(dict(at=now, ip=ip, pid=snapshot['pid'], reason='media-stalled'))
            temporary = path.with_name(path.name + '.' + secrets.token_hex(4))
            with temporary.open('x') as f:
                os.chmod(temporary, 0o600)
                json.dump({'attempts': attempts}, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, path)
            return True

    def tick(self, ip, wanted, progress):
        now = self.monotonic()
        if ip != self.ip:
            self.ip, self.since = ip, now
            self.progress, self.progress_at = progress, now
            self.previous = None
            self.next_snapshot = self.next_install = 0
            self.server_retry = False
        if wanted and not self.wanted:
            self.progress_at = now
            self.previous = None
        self.wanted = wanted
        if not ip:
            self.update('offline', '等待摄像头重新连网')
            return
        if progress != self.progress:
            self.progress, self.progress_at = progress, now
            self.previous = None
            self.server_retry = False
        stalled = wanted and now - self.progress_at >= self.delay
        if now < self.next_install and not stalled:
            self.update('healthy' if wanted else 'idle')
            return
        if now < self.next_snapshot:
            return
        self.next_snapshot = now + 15
        snapshot = parse_snapshot(self.ssh(ip, SNAPSHOT))
        if now >= self.next_install:
            self.install_collector(ip, snapshot)
            self.next_install = now + 300
        if snapshot['core'] and snapshot['core'] != self.last_core:
            self.capture(ip, snapshot)
        if not stalled:
            self.update('healthy' if wanted else 'idle')
            return
        self.update('checking', '视频持续无新数据，正在核验摄像头媒体状态')
        # No reboot during boot, network failures, unknown state or healthy encoder.
        certain = (snapshot['uptime'] is not None and snapshot['uptime'] >= 180
                   and snapshot['rtsp'] == 0
                   and (snapshot['count'] == 0 or
                        (snapshot['count'] == 1 and snapshot['state'] == 'D'
                         and snapshot['frames'] is not None)))
        previous = self.previous
        self.previous = snapshot
        confirmed = (certain and previous is not None
                     and previous['rtsp'] == 0 and previous['count'] == snapshot['count']
                     and previous['pid'] == snapshot['pid']
                     and previous['state'] == snapshot['state']
                     and previous['frames'] == snapshot['frames'])
        if not confirmed:
            if not self.server_retry:
                self.restart()
                self.server_retry = True
                self.event('视频持续停滞，先重建服务器取流连接')
            return
        self.capture(ip, snapshot)
        if not self.reserve_recovery(ip, snapshot):
            self.update('limited', '媒体故障仍存在；自动恢复达到冷却或次数限制')
            return
        self.event('确认摄像头媒体卡死，取证后自动重启恢复；云台将执行开机校准')
        self.update('recovering', '摄像头媒体卡死，正在自动重启恢复')
        # Persist the attempt BEFORE issuing the command, even if SSH subsequently fails.
        reply = self.ssh(ip, '( /bin/busybox sleep 2; /bin/busybox sync; '
                         '/bin/busybox reboot -f ) </dev/null >/tmp/localcam-auto-recovery.log 2>&1 & '
                         'echo MEDIA_RECOVERY_SCHEDULED')
        if b'MEDIA_RECOVERY_SCHEDULED' not in reply:
            raise RuntimeError('摄像头未确认恢复命令')
        self.progress_at = self.monotonic()
        self.previous = None
        self.next_install = 0

    def run(self, activity):
        while not self.stop.is_set():
            try:
                self.tick(*activity())
            except Exception as exc:
                # A failed SSH/identity check can never authorize a reboot.
                self.update('unverified', '媒体健康检查暂时失败，保留现场等待重试')
                self.previous = None
                self.next_snapshot = self.monotonic() + 30
            self.stop.wait(10)
