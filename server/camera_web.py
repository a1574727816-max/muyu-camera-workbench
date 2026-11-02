#!/usr/bin/env python3
"""Single-file LAN camera console. Runtime: FastAPI, uvicorn, paramiko, ffmpeg.

State and credentials live in CAM_DATA (0700); no camera Flash writes are made.
"""
import asyncio
from collections import deque
from contextlib import asynccontextmanager
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
from pathlib import Path
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from urllib.parse import urlsplit
import uuid
import xml.etree.ElementTree as ET

from totp_auth import AuthError, AuthManager
from media_guard import MediaGuard
from multi_camera import CameraHub, CAPABILITIES, PassiveHealth
from rtsp_compat import RTSPCompat

DATA = Path(os.environ.get('CAM_DATA', '/var/lib/cam-manager'))
CONFIG = DATA / 'config.json'
DOMAIN = os.environ.get('CAM_PUBLIC_HOST', 'localhost')
FALLBACK = os.environ.get('CAM_SERVER_IP', '127.0.0.1')
NETWORK = ipaddress.IPv4Network(os.environ.get('CAM_LAN_CIDR', '192.168.1.0/24'))
UUID = os.environ.get('CAM_EXPECTED_UUID', '00000000-0000-4000-8000-000000000001')
MAC = os.environ.get('CAM_EXPECTED_MAC', '02:00:00:00:00:01')
LIMIT = 32_000_000_000  # decimal 32 GB, including the active recording
RESERVE = 256 * 1024 * 1024
TT = 'http://www.onvif.org/ver10/schema'
LOG = logging.getLogger('cam-manager')
PTZ_LEASE = 1.2


def origin_key(value):
    try:
        u = urlsplit(value)
        if (u.scheme not in ('http', 'https') or not u.hostname or u.username is not None
                or u.password is not None or u.path not in ('', '/') or u.query or u.fragment):
            return None
        return u.scheme, u.hostname.lower(), u.port or (443 if u.scheme == 'https' else 80)
    except ValueError:
        return None


def origin_allowed(origin, host, scheme):
    key = origin_key(origin)
    if key is None:
        return False
    configured = [origin_key(s.strip()) for s in os.environ.get('CAM_ALLOWED_ORIGINS', '').split(',') if s.strip()]
    if key in configured:
        return True
    # Preserve Host at the proxy. HTTPS may terminate before this HTTP upstream.
    return key == origin_key(key[0]+'://'+host) and not (scheme == 'https' and key[0] != 'https')


def atomic_json(path, obj):
    temp = path.with_suffix('.new')
    with temp.open('w', encoding='utf-8') as f:
        os.chmod(temp, 0o600)
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def init_config():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    if CONFIG.exists():
        raise SystemExit('Configuration already exists; refusing overwrite')
    supplied = json.load(sys.stdin)
    if 'cameras' in supplied:
        if set(supplied['cameras']) != {'cam1', 'cam2'}:
            raise SystemExit('Configuration must contain cam1 and cam2')
        for camera in supplied['cameras'].values():
            if not camera.get('expected_mac') or not camera.get('expected_uuid'):
                raise SystemExit('Each camera requires its verified MAC and ONVIF UUID')
            lan_ip(camera['manual_ip'])
        if not all(supplied['cameras']['cam1'].get(k) for k in ('camera_password', 'camera_host_key')):
            raise SystemExit('cam1 requires camera_password and a verified camera_host_key')
        atomic_json(CONFIG, supplied)
        return
    atomic_json(CONFIG, dict(camera_password=supplied['camera_password'],
        camera_host_key=supplied['camera_host_key'], expected_mac=supplied.get('expected_mac', MAC),
        expected_uuid=supplied.get('expected_uuid', UUID),
        mode='auto', manual_ip=lan_ip(supplied.get('manual_ip', os.environ.get('CAM_CAMERA_IP', '192.168.1.10'))), recording=True, segment_seconds=600,
        max_recording_bytes=LIMIT, wifi_desired=None))


def lan_ip(value):
    ip = ipaddress.IPv4Address(value)
    if ip not in NETWORK or ip in (NETWORK.network_address, NETWORK.broadcast_address) or str(ip) == FALLBACK:
        raise ValueError('仅支持配置的局域网 ' + str(NETWORK) + ' 中的摄像头地址')
    return str(ip)


def prune(directory, active, target):
    files = sorted(directory.glob('*.mkv'), key=lambda p: p.stat().st_mtime)
    total = sum(p.stat().st_size for p in files)
    removed = []
    for p in files:
        if total <= target:
            break
        if p.name == active:
            continue
        size = p.stat().st_size
        p.unlink()
        total -= size
        removed.append(p.name)
    return total, removed


class Manager:
    def __init__(self, cfg=None, hub=None, camera_id='cam1'):
        self.hub, self.camera_id = hub, camera_id
        self.capabilities = dict(CAPABILITIES[camera_id])
        self.cfg = cfg if cfg is not None else json.loads(CONFIG.read_text())
        absolute_ttl = int(os.environ.get('CAM_SESSION_ABSOLUTE_TTL', str(30 * 24 * 60 * 60)))
        self.auth = hub.auth if hub else AuthManager(
            DATA,
            session_ttl=int(os.environ.get('CAM_SESSION_TTL', str(48 * 60 * 60))),
            absolute_ttl=absolute_ttl or None,
        )
        self.lock = threading.RLock()
        self.ssh_lock = threading.Lock()
        self.ptz_lock = threading.Lock()
        self.ptz_deadline = 0
        self.ptz_motion = None
        self.motor_status_seen = 0
        self.motor_client = None
        self.motor_ip = None
        self.ptz_sequences = {}
        self.motor_status = {}
        self.ptz_error = ''
        self.stop = threading.Event()
        self.wakeup = threading.Event()
        self.rec_dir = DATA / 'recordings' / camera_id if hub else DATA / 'recordings'
        self.rec_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.rec = None
        self.rec_ip = None
        self.rec_prefix = ''
        self.preview = None
        self.preview_ip = None
        self.jpeg = b''
        self.jpeg_seq = 0
        self.preview_seen = 0
        self.preview_time = 0
        self.preview_lock = threading.Lock()
        self.mp4_init = b''
        self.mp4_fragments = deque(maxlen=12)
        self.preview_generation = 0
        self.preview_clients = 0
        self.play_dir = DATA / 'playback-cache' / camera_id if hub else DATA / 'playback-cache'
        self.play_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.playback_jobs = {}
        self.cache_access = {}
        self.recording_info = {}
        self.play_stream_slots = hub.play_stream_slots if hub else threading.BoundedSemaphore(2)
        self.cache_slot = hub.cache_slot if hub else threading.Semaphore(1)
        self.cache_process = None
        self.ip = None
        self.camera = {}
        self.candidates = []
        self.last_discovery = 0
        self.last_full_scan = 0
        self.error = ''
        self.record_error = ''
        self.logs = deque(maxlen=35)
        self.wifi_state = {'state': 'idle', 'message': '网页配置保存在服务器，设备通过固件默认网络可达时自动重下发。'}
        self.wifi_busy = False
        self.last_wifi_check = 0
        self.disk_used = 0
        self.last_removed = []
        self.started = time.time()
        self.media_restart = threading.Event()
        self.media_guard = MediaGuard(
            DATA, self.ssh, self.event, self.media_restart.set, self.stop,
            delay=int(os.environ.get('CAM_MEDIA_STALL_SECONDS', '90')),
            cooldown=int(os.environ.get('CAM_MEDIA_RECOVERY_COOLDOWN', '1800')),
            daily_limit=int(os.environ.get('CAM_MEDIA_RECOVERY_DAILY_LIMIT', '3'))) if self.capabilities['ssh_recovery'] else PassiveHealth()
        self.record_retry_at = 0
        self.record_failures = 0
        self.record_started = 0
        self.rtsp_adapter = None

    def save(self):
        if self.hub:
            self.hub.save()
            return
        with self.lock:
            atomic_json(CONFIG, self.cfg)

    def recording_files(self):
        files = list(self.rec_dir.glob('*.mkv'))
        if self.hub and self.camera_id == 'cam1':
            files.extend((DATA / 'recordings').glob('*.mkv'))
        return [p for p in files if p.is_file() and not p.is_symlink()]

    def cache_files(self):
        files = list(self.play_dir.glob('*.mp4'))
        if self.hub and self.camera_id == 'cam1':
            files.extend((DATA / 'playback-cache').glob('*.mp4'))
        return [p for p in files if p.is_file() and not p.is_symlink()]

    def recording_path(self, name):
        path = self.rec_dir / name
        if not path.exists() and self.hub and self.camera_id == 'cam1':
            path = DATA / 'recordings' / name
        return path

    def rtsp_url(self):
        if getattr(self,'camera_id','cam1') == 'cam2' and self.cfg.get('rtcp_keepalive',True):
            if self.rtsp_adapter is None:
                self.rtsp_adapter = RTSPCompat(lambda:self.ip,self.stop)
            return self.rtsp_adapter.url()
        return 'rtsp://' + self.ip + ':554/stream1'

    def rtsp_input(self):
        args = ['-rtsp_transport','tcp','-timeout','10000000']
        if getattr(self,'camera_id','cam1') == 'cam2':
            # Older firmware's audio RTCP clock may jump by hours. Preserve
            # encoded packets but timestamp their arrival on the server clock.
            args += ['-use_wallclock_as_timestamps','1','-fflags','+genpts']
        return args + ['-i',self.rtsp_url()]

    def scoped_url(self, path):
        return path + ('&' if '?' in path else '?') + 'camera_id=' + self.camera_id

    def event(self, text):
        with self.lock:
            self.logs.append({'time': time.strftime('%H:%M:%S'), 'text': text})
        LOG.info('%s', text)

    def ssh(self, ip, command, data=None, timeout=12, max_bytes=150000):
        if not self.capabilities['ssh_recovery']:
            raise ValueError('该摄像头未开放SSH管理')
        import paramiko
        # The identity is pinned, independent of DHCP IP and discovery responses.
        key_type, key_data = self.cfg['camera_host_key'].split()[:2]
        import base64
        key = paramiko.Ed25519Key(data=base64.b64decode(key_data))
        c = paramiko.SSHClient()
        c.get_host_keys().add('[' + ip + ']:2222', key_type, key)
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        with self.ssh_lock:
            c.connect(ip, port=2222, username='root', password=self.cfg['camera_password'],
                      allow_agent=False, look_for_keys=False, timeout=5, auth_timeout=5, banner_timeout=5)
            try:
                i, o, e = c.exec_command(command, timeout=timeout)
                if data is not None:
                    i.write(data)
                    i.flush()
                i.channel.shutdown_write()
                out, err = o.read(max_bytes + 1), e.read(2000)
                if len(out) > max_bytes:
                    raise RuntimeError('摄像头命令输出超过读取上限')
                rc = o.channel.recv_exit_status()
                if rc:
                    raise RuntimeError('摄像头命令失败，退出码 ' + str(rc))
                return out
            finally:
                c.close()

    def soap(self, ip, action, body='', ptz=False):
        ns = 'http://www.onvif.org/ver20/ptz/wsdl' if ptz else 'http://www.onvif.org/ver10/device/wsdl'
        payload = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tt="' + TT +
                   '"><s:Body><' + action + ' xmlns="' + ns + '">' + body + '</' + action +
                   '></s:Body></s:Envelope>').encode()
        url = 'http://' + ip + ':' + str(self.cfg.get('onvif_port',8899)) + '/onvif/' + ('ptz_service' if ptz else 'device_service')
        handlers = [urllib.request.ProxyHandler({})]
        if ptz:
            auth = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            auth.add_password('LocalCamera', url, 'root', self.cfg['camera_password'])
            handlers.append(urllib.request.HTTPDigestAuthHandler(auth))
        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/soap+xml'})
        with urllib.request.build_opener(*handlers).open(req, timeout=4) as r:
            tree = ET.fromstring(r.read(150000))
        if any(e.tag.endswith('}Fault') for e in tree.iter()):
            raise RuntimeError('ONVIF 返回错误')
        return tree

    def neighbours(self):
        raw = subprocess.run(['ip', '-j', 'neigh'], capture_output=True, timeout=4).stdout
        return {r['dst']: r.get('lladdr', '').lower() for r in json.loads(raw or b'[]')
                if r.get('dst') and ipaddress.ip_address(r['dst']) in NETWORK}

    def probes(self):
        payload = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:n="http://www.onvif.org/ver10/network/wsdl"><s:Header><a:MessageID>uuid:' + str(uuid.uuid4()) +
            '</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
            '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></s:Header>'
            '<s:Body><d:Probe><d:Types>n:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>').encode()
        found = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((os.environ.get('CAM_DISCOVERY_BIND', '0.0.0.0'), 0))
            s.settimeout(.3)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            s.sendto(payload, ('239.255.255.250', 3702))
            end = time.monotonic() + 1.2
            while time.monotonic() < end:
                try:
                    raw, address = s.recvfrom(32768)
                    ip = lan_ip(address[0])
                    tree = ET.fromstring(raw)
                    addresses = [e.text or '' for e in tree.iter() if e.tag.endswith('}Address')]
                    expected = self.cfg['expected_uuid'].removeprefix('uuid:')
                    found[ip] = bool(expected) and any(expected == value.removeprefix('uuid:') for value in addresses)
                except (socket.timeout, ValueError, ET.ParseError):
                    continue
        return found

    def identify(self, ip, neighbours, discovered):
        try:
            ip = lan_ip(ip)
            tree = self.soap(ip, 'GetDeviceInformation')
            fields = {e.tag.split('}')[-1]: e.text for e in tree.iter() if e.text and not list(e)}
            if not fields.get('Model'):
                return None
            mac = self.neighbours().get(ip, neighbours.get(ip, ''))
            match = bool(self.cfg['expected_mac']) and mac == self.cfg['expected_mac'] or discovered.get(ip, False)
            return {'ip': ip, 'mac': mac, 'model': fields.get('Model'),
                    'manufacturer': fields.get('Manufacturer'), 'bound_match': match,
                    'uuid_match': discovered.get(ip, False)}
        except Exception:
            return None

    def discover(self):
        from concurrent.futures import ThreadPoolExecutor
        neighbours = self.neighbours()
        discovered = self.probes()
        ips = set(neighbours) | set(discovered) | {self.cfg['manual_ip']}
        if self.capabilities['ssh_recovery'] and self.cfg.get('fallback_ip'):
            ips.add(lan_ip(self.cfg['fallback_ip']))
        if self.ip:
            ips.add(self.ip)
        # Discovery/ARP normally suffice. Bounded /24 port search is a fallback.
        if not discovered and not self.ip and time.time() - self.last_full_scan > 180:
            def open_port(ip):
                try:
                    with socket.create_connection((ip, self.cfg.get('onvif_port',8899)), timeout=.18):
                        return ip
                except OSError:
                    return None
            with ThreadPoolExecutor(max_workers=24) as pool:
                # Limit fallback scanning to at most 254 hosts even on a large subnet.
                from itertools import islice
                targets = (str(ip) for ip in islice(NETWORK.hosts(), 254) if str(ip) != FALLBACK)
                ips.update(x for x in pool.map(open_port, targets) if x)
            self.last_full_scan = time.time()
        with ThreadPoolExecutor(max_workers=12) as pool:
            candidates = [r for r in pool.map(lambda ip: self.identify(ip, neighbours, discovered), ips) if r]
        with self.lock:
            self.candidates = candidates
            self.last_discovery = time.time()
        wanted = (next((c for c in candidates if c['ip'] == self.cfg['manual_ip']), None)
                  if self.cfg['mode'] == 'manual' else next((c for c in candidates if c['bound_match']), None))
        if wanted:
            if not wanted['bound_match']:
                self.error = '指定IP与绑定的MAC/UUID不符，已拒绝连接'
                self.ip = None
                return
            old = self.ip
            # Pin SSH key before selecting even a manually supplied ONVIF device.
            if old != wanted['ip'] and self.capabilities['ssh_recovery']:
                info = self.ssh(wanted['ip'], '/bin/busybox cat /sys/class/net/wlan0/address; /bin/busybox cat /sys/class/net/eth0/address')
                if self.cfg['expected_mac'].encode() not in info:
                    raise RuntimeError('设备 MAC 与绑定身份不符')
            with self.lock:
                self.ip, self.camera = wanted['ip'], wanted
            if old != self.ip:
                self.event('已连接' + self.cfg.get('name','摄像头') + ' ' + self.ip + '，绑定身份核对通过')
            self.error = ''
        else:
            self.error = '暂未发现绑定摄像头；等待自动重试，或手动配置 IP'
            self.ip = None

    def active_name(self):
        with self.lock:
            return self._active_name()

    def _active_name(self):
        if self.rec and self.rec.poll() is None:
            files = list(self.rec_dir.glob(self.rec_prefix + '*.mkv'))
            if files:
                return max(files, key=lambda p:p.name).name
        return None

    def stop_process(self, p):
        if p and p.poll() is None:
            p.send_signal(signal.SIGINT)
            try:
                p.wait(timeout=6)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)

    def drain(self, p, recording):
        for raw in p.stderr:
            text = raw.decode(errors='replace').strip()[:350]
            if text:
                if recording and any(word in text.lower() for word in ['error', 'failed', 'timed out']):
                    self.record_error = '录像传输出现错误，正在自动重连'
                LOG.warning('ffmpeg %s: %s', 'record' if recording else 'preview', text)

    def recorder_tick(self):
        if self.rec and (not self.cfg['recording'] or not self.ip or self.rec_ip != self.ip):
            self.stop_process(self.rec)
            self.rec = None
        active = self.active_name()
        cache_bytes = self.cache_tick()
        if getattr(self, 'hub', None):
            self.disk_used, removed = self.hub.prune()
        else:
            with self.lock:
                self.disk_used, removed = prune(self.rec_dir, active, self.cfg['max_recording_bytes'] - RESERVE - cache_bytes)
        if removed:
            self.last_removed = removed[-5:]
            self.event('空间轮转：清理 ' + str(len(removed)) + ' 个最旧已完成片段')
        disk = os.statvfs(self.rec_dir)
        free = disk.f_bavail * disk.f_frsize
        free_floor = self.hub.min_free_bytes if getattr(self, 'hub', None) else RESERVE
        if self.disk_used >= self.cfg['max_recording_bytes'] or free < free_floor:
            self.stop_process(self.rec)
            self.rec = None
            self.record_error = '存储空间不足，录像暂停；已完成片段仍可访问'
            return
        if self.rec and self.rec.poll() is not None:
            self.record_failures = (0 if time.monotonic() - self.record_started > 30
                                    else self.record_failures + 1)
            self.record_retry_at = time.monotonic() + min(30, 2 ** min(5, self.record_failures))
            self.rec = None
            self.record_error = '录像连接中断，正在自动重连'
        if (self.cfg['recording'] and self.ip and self.rec is None
                and time.monotonic() >= self.record_retry_at):
            self.rec_prefix = time.strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3) + '-'
            dest = str(self.rec_dir / (self.rec_prefix + '%06d.mkv'))
            args = ['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'warning'] + self.rtsp_input() + [
                    '-map', '0:v:0', '-map', '0:a?', '-c', 'copy', '-f', 'segment',
                    '-segment_time', str(self.cfg['segment_seconds']), '-reset_timestamps', '1',
                    '-segment_format', 'matroska', dest]
            # Publish the writer while quota pruning is excluded, so another
            # camera cannot unlink a just-created first segment.
            with self.hub.storage_lock if getattr(self,'hub',None) else self.lock:
                self.rec = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self.record_started = time.monotonic()
                self.rec_ip = self.ip
            self.record_error = ''
            threading.Thread(target=self.drain, args=(self.rec, True), daemon=True).start()
            self.event('服务器原码流录像已启动，每 10 分钟分段')

    def read_preview(self, p):
        buf = bytearray()
        init = bytearray()
        fragment = bytearray()
        while not self.stop.is_set():
            chunk = p.stdout.read1(65536)
            if not chunk:
                break
            buf.extend(chunk)
            while True:
                if len(buf) < 8:
                    break
                size = int.from_bytes(buf[:4], 'big')
                kind = bytes(buf[4:8])
                if size == 1:
                    if len(buf) < 16:
                        break
                    size = int.from_bytes(buf[8:16], 'big')
                if size < 8 or size > 16_000_000:
                    return
                if len(buf) < size:
                    break
                box = bytes(buf[:size])
                del buf[:size]
                if kind in (b'ftyp', b'moov'):
                    init.extend(box)
                elif kind == b'moof':
                    fragment = bytearray(box)
                elif kind == b'mdat' and fragment:
                    fragment.extend(box)
                    with self.preview_lock:
                        if self.preview is not p:
                            return
                        self.mp4_init = bytes(init)
                        self.jpeg_seq += 1
                        self.mp4_fragments.append((self.jpeg_seq, bytes(fragment)))
                        self.preview_time = time.time()
                    fragment.clear()

    def preview_tick(self):
        wanted = self.ip if time.time() - self.preview_seen < 12 else None
        if self.preview and (self.preview_ip != wanted or self.preview.poll() is not None):
            self.stop_process(self.preview)
            self.preview = None
        if wanted and self.preview is None:
            with self.preview_lock:
                self.preview_generation += 1
                self.mp4_init = b''
                self.mp4_fragments.clear()
            args = ['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'warning'] + self.rtsp_input() + [
                    '-map', '0:v:0', '-map', '0:a:0?', '-vf', 'fps=15,scale=960:-2',
                    '-c:v', 'libx264', '-preset', 'ultrafast', '-tune', 'zerolatency',
                    '-profile:v', 'baseline', '-level:v', '3.1', '-pix_fmt', 'yuv420p', '-crf', '25',
                    '-maxrate', '1200k', '-bufsize', '1200k',
                    '-g', '15', '-keyint_min', '15', '-sc_threshold', '0', '-threads', '2',
                    '-c:a', 'aac', '-b:a', '64k', '-ar', '48000', '-ac', '1',
                    *(['-af','aresample=async=1:first_pts=0'] if getattr(self,'camera_id','cam1')=='cam2' else []),
                    '-f', 'mp4', '-movflags', '+empty_moov+default_base_moof+frag_keyframe',
                    '-flush_packets', '1', 'pipe:1']
            self.preview = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.preview_ip = wanted
            threading.Thread(target=self.drain, args=(self.preview, False), daemon=True).start()
            threading.Thread(target=self.read_preview, args=(self.preview,), daemon=True).start()

    def run(self):
        # Only the owning service cleans its interrupted conversion files.
        # Read-only diagnostics may construct a Manager in another process.
        for old in self.play_dir.glob('*.part.mp4'):
            old.unlink(missing_ok=True)
        if self.capabilities['ssh_recovery']:
            guard = threading.Thread(target=self.media_guard.run, args=(self.media_activity,), daemon=True)
            guard.start()
        next_discovery = 0
        while not self.stop.is_set():
            try:
                if time.time() >= next_discovery or self.wakeup.is_set():
                    self.wakeup.clear()
                    try:
                        self.discover()
                    except Exception as exc:
                        self.error = '发现/身份核验暂时失败：' + type(exc).__name__
                    next_discovery = time.time() + 25
                if self.media_restart.is_set():
                    self.media_restart.clear()
                    self.stop_process(self.rec)
                    self.stop_process(self.preview)
                    self.rec = self.preview = None
                    self.record_retry_at = 0
                self.recorder_tick()
                self.preview_tick()
                if self.capabilities['wifi'] and self.cfg.get('wifi_desired') and self.ip and not self.wifi_busy and time.time() - self.last_wifi_check > 60:
                    self.last_wifi_check = time.time()
                    current = self.ssh(self.ip, '/bin/busybox md5sum /etc/localcam/wpa.conf').decode().split()[0]
                    if current != self.cfg['wifi_desired']['md5']:
                        self.start_wifi(self.cfg['wifi_desired'])
                    else:
                        self.wifi_state = {'state': 'applied', 'ssid': self.cfg['wifi_desired']['ssid'],
                            'message': '当前配置与服务器保存项一致。断电后先通过默认无线网络 或网线联系服务器，再自动下发。'}
            except Exception as exc:
                LOG.warning('supervisor: %s', type(exc).__name__)
            self.stop.wait(1)
        self.stop_process(self.rec)
        self.stop_process(self.preview)
        self.stop_process(self.cache_process)

    def media_activity(self):
        """Observe existing streams; health checks open no extra RTSP sessions."""
        wanted = bool(self.cfg['recording'] or time.time() - self.preview_seen < 12)
        name = self.active_name()
        try:
            size = (self.rec_dir / name).stat().st_size if name else 0
        except OSError:
            size = 0
        # Size may fall at segment rollover; either change is forward progress.
        return self.ip, wanted, (name if size > 8192 else None,
                                size if size > 8192 else 0, self.preview_time)

    def motor(self, operation, pan=None, tilt=None, pan_speed=1, tilt_speed=1):
        """Pinned persistent SSH; no ONVIF RPC/watchdog pipe for web controls."""
        import paramiko, base64
        for attempt in range(2):
            try:
                if self.motor_client is None or self.motor_ip != self.ip or not self.motor_client.get_transport().is_active():
                    if self.motor_client:
                        self.motor_client.close()
                    kind, raw = self.cfg['camera_host_key'].split()[:2]
                    key = paramiko.Ed25519Key(data=base64.b64decode(raw))
                    c = paramiko.SSHClient()
                    c.get_host_keys().add('['+self.ip+']:2222', kind, key)
                    c.set_missing_host_key_policy(paramiko.RejectPolicy())
                    c.connect(self.ip, port=2222, username='root', password=self.cfg['camera_password'],
                              allow_agent=False, look_for_keys=False, timeout=4, auth_timeout=4, banner_timeout=4)
                    c.get_transport().set_keepalive(15)
                    self.motor_client, self.motor_ip = c, self.ip
                    self.ptz_motion = None
                command = '/bin/ubus -t 2 call motord '
                if operation == 'goto':
                    value = json.dumps({'x_coord': str(int(pan)), 'y_coord': str(int(tilt))})
                    command += 'moveTo ' + shlex.quote(value)
                elif operation == 'track':
                    value = json.dumps({'x_coord':str(int(pan)), 'y_coord':str(int(tilt)),
                                        'x_speed':str(int(pan_speed)), 'y_speed':str(int(tilt_speed))})
                    command += 'targetTrack '+shlex.quote(value)
                elif operation in ('getStatus', 'stop'):
                    command += operation
                else:
                    raise ValueError('无效电机操作')
                i, o, e = self.motor_client.exec_command(command, timeout=4)
                i.channel.shutdown_write()
                raw, errors = o.read(8192), e.read(2048)
                rc = o.channel.recv_exit_status()
                if rc:
                    raise RuntimeError('电机服务没有及时回应')
                result = json.loads(raw)
                if result.get('error_code') != 0:
                    diagnostic = {'operation':operation,'target':[pan,tilt],
                        'error_code':result.get('error_code'),'last_status':self.motor_status,'time':time.time()}
                    atomic_json(DATA/'motor-last-error.json',diagnostic)
                    LOG.warning('Motor rejected: %s',json.dumps(diagnostic))
                    raise RuntimeError('电机参数超出有效范围（-64302）' if result.get('error_code')==-64302
                                       else '电机动作未完成，返回码 '+str(result.get('error_code')))
                if operation == 'getStatus':
                    self.motor_status = result['status']
                    self.motor_status_seen = time.monotonic()
                self.ptz_error = ''
                return result
            except (OSError, paramiko.SSHException, EOFError):
                if self.motor_client:
                    self.motor_client.close()
                self.motor_client = None
                if attempt:
                    raise RuntimeError('摄像头管理连接中断，请等待重新连接')

    def ptz(self, x, y, sequence=None, controller='', mode='continuous'):
        if not self.capabilities['ptz']:
            raise ValueError('该摄像头未开放云台控制')
        if not self.ip:
            raise ValueError('摄像头离线')
        x, y = float(x), float(y)
        import math
        if not math.isfinite(x) or not math.isfinite(y):
            raise ValueError('无效方向')
        x, y = max(-1., min(1., x)), max(-1., min(1., y))
        if mode not in ('continuous', 'step'):
            raise ValueError('无效控制模式')
        if sequence is not None:
            if type(sequence) is not int or sequence < 0:
                raise ValueError('无效控制序号')
            with self.lock:
                self.ptz_sequences[controller] = max(sequence, self.ptz_sequences.get(controller, -1))
        with self.ptz_lock:
            if sequence is not None and sequence < self.ptz_sequences.get(controller, -1):
                return {'ok': True, 'superseded': True}
            if abs(x) + abs(y) < .05:
                self.motor('stop')
                self.ptz_deadline = 0
                self.ptz_motion = None
                return {'ok':True,'stopped':True,'message':'已停止'}
            elif mode == 'continuous':
                now = time.monotonic()
                def axis(value, index):
                    if abs(value)<.12:
                        return 0,1
                    sign = 1 if value>0 else -1
                    speed = max(1,min(9,round(abs(value)*9)))
                    # Avoid repeated speed resets from small joystick hand tremors.
                    if (self.ptz_motion and self.ptz_motion[index]==sign
                            and abs(abs(value)*9-self.ptz_motion[index+2])<.8):
                        speed = self.ptz_motion[index+2]
                    return sign,speed
                (ax,sx),(ay,sy) = axis(x,0),axis(y,1)
                # This motor advertises simultaneous=disabled. A long diagonal
                # targetTrack blocks its RPC loop, including Stop, until one axis ends.
                # Keep diagonal control on the dominant axis, with a crossover deadband.
                if ax and ay:
                    previous = self.ptz_motion or (0,0,1,1)
                    if previous[0] and abs(x)>=abs(y)*.85:
                        ay=0
                    elif previous[1] and abs(y)>=abs(x)*.85:
                        ax=0
                    elif abs(x)>=abs(y):
                        ay=0
                    else:
                        ax=0
                if not ax:sx=1
                if not ay:sy=1
                intent = (ax,ay,sx,sy)
                if (intent != self.ptz_motion or now-self.motor_status_seen>.45
                        or self.motor_ip != self.ip or not self.ptz_deadline):
                    status = self.motor('getStatus')['status']
                else:
                    status = self.motor_status
                # Stock targetTrack rejects a changed target while busy (-64303).
                # Stop only for a real direction/speed change, never a heartbeat.
                if intent != self.ptz_motion and (self.ptz_deadline or
                        int(status['x_speed']) or int(status['y_speed'])):
                    self.motor('stop')
                    self.ptz_motion = None
                    self.ptz_deadline = 0
                    status = self.motor('getStatus')['status']
                cx,cy = int(status['x_coord']),int(status['y_coord'])
                limits = []
                if (ax>0 and cx>=149) or (ax<0 and cx<=-149):
                    limits.append('水平'+('右' if ax>0 else '左')+'限位');ax=0
                if (ay>0 and cy>=84) or (ay<0 and cy<=-30):
                    limits.append('垂直'+('上' if ay>0 else '下')+'限位');ay=0
                motion = (ax,ay,sx,sy)
                if ax or ay:
                    if motion != self.ptz_motion or not self.ptz_deadline:
                        tx = (150 if ax>0 else -150) if ax else cx
                        ty = (85 if ay>0 else -30) if ay else cy
                        self.motor('track',tx-cx,ty-cy,sx,sy)
                        self.ptz_motion = motion
                    self.ptz_deadline = time.monotonic()+PTZ_LEASE
                else:
                    if self.ptz_motion != motion:
                        self.motor('stop')
                    self.ptz_motion = motion
                    self.ptz_deadline = 0
                return {'ok':True,'timeout_seconds':PTZ_LEASE,'transport':'pinned-ssh-targetTrack',
                        'limited':bool(limits),'message':'已到'+'、'.join(limits) if limits else
                        ('持续水平转动中' if ax else '持续垂直转动中' if ay else '已停止')}
            else:
                self.ptz_motion = None
                status = self.motor('getStatus')['status']
                cx, cy = int(status['x_coord']), int(status['y_coord'])
                dx = 0 if (cx >= 149 and x > 0) or (cx <= -149 and x < 0) else max(-150, min(150, round(cx+x*6)))-cx
                # Stock getCapa advertises -90, but moveTo rejects every y<-30.
                dy = 0 if (cy >= 84 and y > 0) or (cy <= -30 and y < 0) else max(-30, min(85, round(cy+y*6)))-cy
                limit = []
                if abs(x)>.1 and dx==0:
                    limit.append('水平'+('右' if x>0 else '左')+'限位')
                if abs(y)>.1 and dy==0:
                    limit.append('垂直'+('上' if y>0 else '下')+'限位')
                if dx or dy:
                    self.motor('goto', cx+dx, cy+dy)
                    self.ptz_deadline = time.monotonic()+.5
                else:
                    self.motor('stop')
                    self.ptz_deadline = 0
                return {'ok':True,'timeout_seconds':.5,'transport':'pinned-ssh-moveTo',
                        'limited':bool(limit),'message':'已到'+ '、'.join(limit) if limit else '移动中'}
        return {'ok': True, 'timeout_seconds': .5, 'transport': 'pinned-ssh-moveTo'}

    def ptz_watchdog(self):
        while not self.stop.wait(.05):
            if self.ptz_deadline and time.monotonic() >= self.ptz_deadline:
                with self.ptz_lock:
                    if self.ptz_deadline and time.monotonic() >= self.ptz_deadline:
                        try:
                            self.motor('stop')
                        except Exception:
                            LOG.warning('PTZ stop retry pending')
                            self.ptz_deadline = time.monotonic()+1
                        else:
                            self.ptz_deadline = 0
                            self.ptz_motion = None

    def cache_tick(self):
        if getattr(self, 'hub', None):
            self.hub.prune()
            return self.hub.usage()[1]
        with self.lock:
            files = sorted(self.play_dir.glob('*.mp4'),
                           key=lambda p:self.cache_access.get(p.stem+'.mkv',p.stat().st_mtime))
            total = sum(p.stat().st_size for p in files)
            for p in files:
                if p.name.endswith('.part.mp4'):
                    continue
                original = self.rec_dir / (p.stem + '.mkv')
                if not original.exists() or total > 512*1024*1024:
                    total -= p.stat().st_size
                    p.unlink()
            return total

    def playback_info(self,path):
        with self.lock:
            if path.name in self.recording_info:
                return self.recording_info[path.name]
        p = subprocess.run(['ffprobe','-v','error','-show_entries','format=duration:stream=codec_name',
            '-of','json',str(path)],capture_output=True,timeout=15,check=True)
        info = json.loads(p.stdout)
        result = {'duration':float(info['format']['duration']),
                  'has_audio':any(s.get('codec_name') not in ('h264','hevc') for s in info['streams'])}
        with self.lock:
            self.recording_info[path.name] = result
        return result

    def prepare_playback(self, path):
        if self.hub:
            with self.hub.storage_lock:
                if not path.is_file():
                    raise ValueError('录像已被容量轮转清理')
                self.hub.pin(path)
            try:
                return self._prepare_playback(path)
            finally:
                self.hub.unpin(path)
        return self._prepare_playback(path)

    def _prepare_playback(self, path):
        name = path.name
        target = self.play_dir / (path.stem+'.mp4')
        metadata = {**self.playback_info(path),'stream_url':self.scoped_url('/api/play/'+name+'/stream')}
        with self.lock:
            if target.exists():
                return {**metadata,'state':'ready','progress':100,'url':self.scoped_url('/api/play/'+name)}
            if name in self.playback_jobs and self.playback_jobs[name]['state'] in ('queued','processing'):
                return {**metadata,**self.playback_jobs[name]}
            if sum(j['state'] in ('queued','processing') for j in self.playback_jobs.values()) >= 4:
                return {**metadata,'state':'stream-only','progress':0}
            self.playback_jobs[name] = {'state':'queued','progress':0}
            if self.hub:
                self.hub.pin(path)
            threading.Thread(target=self.convert_playback, args=(path,target), daemon=True).start()
            return {**metadata,**self.playback_jobs[name]}

    def convert_playback(self, path, target):
        with self.cache_slot:
            temporary = target.with_name(target.stem+'.part.mp4')
            try:
                if self.stop.is_set():
                    return
                duration = self.playback_info(path)['duration']
                with self.lock:
                    self.playback_jobs[path.name] = {'state':'processing','progress':0,'duration':duration}
                self.cache_tick()
                if self.hub:
                    disk = os.statvfs(self.play_dir)
                    if disk.f_bavail * disk.f_frsize < self.hub.min_free_bytes:
                        raise RuntimeError('服务器磁盘空间不足，暂停回放缓存，请稍后重试')
                args = ['ffmpeg','-nostdin','-hide_banner','-loglevel','error','-y','-i',str(path),
                    '-map','0:v:0','-map','0:a:0?','-vf','fps=15,scale=1280:-2',
                    '-c:v','libx264','-preset','ultrafast','-tune','zerolatency',
                    '-profile:v','baseline','-level:v','3.1','-crf','23','-maxrate','2M','-bufsize','4M',
                    '-g','30','-keyint_min','30','-sc_threshold','0','-pix_fmt','yuv420p','-threads','2',
                    '-c:a','aac','-b:a','64k','-ar','48000','-ac','1',
                    '-af','aresample=async=1:first_pts=0',
                    '-movflags','+empty_moov+default_base_moof+frag_keyframe','-flush_packets','1',
                    '-progress','pipe:1',str(temporary)]
                p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
                self.cache_process = p
                # Error output is bounded by this command's loglevel; drain concurrently.
                errors = bytearray()
                def drain_errors():
                    for chunk in iter(lambda:p.stderr.read(4096), b''):
                        if len(errors)<8192:
                            errors.extend(chunk[:8192-len(errors)])
                threading.Thread(target=drain_errors, daemon=True).start()
                for line in p.stdout:
                    if self.hub:
                        disk = os.statvfs(self.play_dir)
                        if disk.f_bavail * disk.f_frsize < self.hub.min_free_bytes:
                            self.stop_process(p)
                            raise RuntimeError('服务器磁盘空间不足，已停止回放缓存')
                    if line.startswith(b'out_time_us='):
                        value = min(99,round(int(line.split(b'=')[1])/1e6/duration*100))
                        with self.lock:
                            self.playback_jobs[path.name]['progress'] = value
                if p.wait(timeout=10) != 0 or not temporary.exists():
                    raise RuntimeError('回放转换失败，请稍后重试')
                with self.lock:
                    os.replace(temporary,target)
                    self.playback_jobs[path.name] = {'state':'ready','progress':100,'duration':duration,
                        'url':self.scoped_url('/api/play/'+path.name),'audio':'AAC','video':'H264'}
                self.cache_tick()
            except Exception as exc:
                with self.lock:
                    self.playback_jobs[path.name] = {'state':'error','progress':0,
                        'message':str(exc) if isinstance(exc,RuntimeError) else '回放准备失败，请重试'}
            finally:
                self.cache_process = None
                temporary.unlink(missing_ok=True)
                if self.hub:
                    self.hub.unpin(path)

    def start_wifi(self, desired):
        if not self.capabilities['wifi']:
            raise ValueError('该摄像头不支持网页Wi-Fi配置')
        if self.wifi_busy:
            raise ValueError('Wi-Fi 切换正在进行')
        if not self.ip:
            raise ValueError('摄像头离线')
        self.wifi_busy = True
        self.wifi_state = {'state': 'switching', 'message': '正在测试新网络，失败约 60 秒自动回退。'}
        threading.Thread(target=self.wifi_worker, args=(self.ip, desired), daemon=True).start()

    def wifi_worker(self, old_ip, desired):
        # Volatile bind mount only; firmware/defaults and raw Flash remain untouched.
        script = r'''set -e
BB=/bin/busybox
umask 077
mkdir -p /tmp/cam-web-wifi
if [ ! -f /tmp/cam-web-wifi/base ]; then
  $BB cp /etc/localcam/wpa.conf /tmp/cam-web-wifi/base
  $BB cp /etc/localcam/wpa.conf /tmp/cam-web-wifi/current
  $BB mount -o bind /tmp/cam-web-wifi/current /etc/localcam/wpa.conf
fi
$BB cp /tmp/cam-web-wifi/current /tmp/cam-web-wifi/rollback.$TOKEN
$BB cat > /tmp/cam-web-wifi/current
$BB rm -f /tmp/cam-web-wifi/confirmed.$TOKEN
(trap '' HUP; $BB sleep 60
 if [ ! -f /tmp/cam-web-wifi/confirmed.$TOKEN ]; then
   $BB cat /tmp/cam-web-wifi/rollback.$TOKEN > /tmp/cam-web-wifi/current
   p=$($BB cat /tmp/localcam-managed-wpa.pid)
   case "$p" in ''|*[!0-9]*) exit 1;; esac
   $BB kill -TERM "$p"
 fi) >/tmp/cam-web-wifi/rollback.log 2>&1 </dev/null &
(trap '' HUP; $BB sleep 2; p=$($BB cat /tmp/localcam-managed-wpa.pid)
 case "$p" in ''|*[!0-9]*) exit 1;; esac
 $BB kill -TERM "$p") >/dev/null 2>&1 </dev/null &
echo WIFI_TEST_SCHEDULED
'''
        try:
            data = desired['config'].encode()
            token = secrets.token_hex(8)
            self.ssh(old_ip, '/bin/sh -c ' + shlex.quote('TOKEN=' + token + '\n' + script), data=data)
            time.sleep(6)
            until = time.time() + 42
            while time.time() < until and not self.stop.is_set():
                ips = {old_ip} | set(self.probes())
                ips.update(ip for ip, mac in self.neighbours().items() if mac == self.cfg['expected_mac'])
                for ip in ips:
                    try:
                        actual = self.ssh(lan_ip(ip), '/bin/busybox md5sum /etc/localcam/wpa.conf; '
                                          '/usr/sbin/iwconfig wlan0; /bin/busybox cat /sys/class/net/wlan0/carrier')
                        if desired['md5'].encode() in actual and desired['ssid'].encode() in actual and actual.rstrip().endswith(b'1'):
                            self.ssh(ip, '/bin/busybox touch /tmp/cam-web-wifi/confirmed.' + token)
                            with self.lock:
                                self.cfg['wifi_desired'] = desired
                                self.cfg['manual_ip'] = ip
                                self.ip = ip
                                self.save()
                            self.wifi_state = {'state': 'applied', 'ssid': desired['ssid'], 'ip': ip,
                                'message': '切换成功；服务器已保存。重启后先用固件默认无线网络 或网线联系服务器，再自动下发。'}
                            self.event('Wi-Fi 测试成功；配置已保存在服务器')
                            self.wakeup.set()
                            return
                    except Exception:
                        continue
                time.sleep(2)
            self.wifi_state = {'state': 'rollback', 'message': '未确认新网络可达，设备将自动回退；未保存新配置。'}
        except Exception as exc:
            self.wifi_state = {'state': 'error', 'message': '切换未完成：' + type(exc).__name__ + '；已安排的测试会自动回退。'}
        finally:
            self.wifi_busy = False

    def state(self, offset=0):
        with self.lock:
            if self.hub:
                with self.hub.storage_lock:
                    return self._state(offset)
            return self._state(offset)

    def _state(self, offset=0):
        active = self.active_name()
        files = sorted(self.recording_files(), key=lambda p:p.name, reverse=True)
        storage_bytes, cache_bytes = self.hub.usage() if self.hub else (
            sum(p.stat().st_size for p in files)+sum(p.stat().st_size for p in self.cache_files()),
            sum(p.stat().st_size for p in self.cache_files()))
        return dict(ip=self.ip, camera=self.camera, candidates=self.candidates, mode=self.cfg['mode'],
            camera_id=self.camera_id, camera_name=self.cfg.get('name','摄像头一'), capabilities=dict(self.capabilities),
            cameras=self.hub.cameras() if self.hub else [], video_codec=self.cfg.get('video_codec','H.265'),
            video_resolution=self.cfg.get('video_resolution','1920×1080'),
            manual_ip=self.cfg['manual_ip'], online=bool(self.ip), error=self.error,
            ptz_error=self.ptz_error, motor_status=dict(self.motor_status),
            recording_enabled=self.cfg['recording'], recording=bool(self.rec and self.rec.poll() is None),
            recording_error=self.record_error or self.media_guard.status()['message'],
            media_health=self.media_guard.status(),
            active_file=active, segment_seconds=self.cfg['segment_seconds'],
            storage_bytes=storage_bytes, playback_cache_bytes=cache_bytes,
            storage_limit_bytes=self.cfg['max_recording_bytes'],
            recordings=[dict(name=p.name, bytes=p.stat().st_size, mtime=p.stat().st_mtime, active=p.name == active)
                        for p in files[offset:offset+100]], total_recordings=len(files),
            recordings_offset=offset, recordings_has_more=len(files)>offset+100,
            wifi=self.wifi_state, wifi_default=self.cfg.get('wifi_default_ssid', ''), wifi_server_saved=bool(self.cfg.get('wifi_desired')),
            server_url='http://' + DOMAIN, fallback_url='http://' + FALLBACK,
            server_receive_mode='server-pull-rtsp-tcp', identity_mac=self.cfg['expected_mac'],
            last_discovery=self.last_discovery, preview_age=round(time.time()-self.preview_time, 1) if self.preview_time else None,
            logs=list(self.logs), recording_format='MKV / original H.265 + original audio',
            wifi_persistence='server-reapply-when-reachable; factory-default-on-camera-cold-boot')


HTML = r'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MuYu · Camera</title>
<style>
:root{color-scheme:dark;--bg:#101315;--panel:#191e21;--line:#30383d;--muted:#98a6ad;--green:#b6ed7d;--red:#f38d80}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#eef3f5;font:14px system-ui,"Microsoft YaHei",sans-serif}button,input,select{font:inherit}button{cursor:pointer;background:#293238;color:#eef3f5;border:1px solid #435059;border-radius:7px;padding:9px 14px}button:hover{background:#3b484f}button.primary{background:var(--green);color:#192216;border-color:var(--green);font-weight:650}button.danger{color:var(--red)}button:disabled{opacity:.4;cursor:wait}input,select{width:100%;background:#101518;color:#f1f5f6;border:1px solid #3a454c;padding:10px;border-radius:6px;outline:none}input:focus{border-color:var(--green)}a{color:var(--green)}header{height:76px;padding:0 34px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}.brand{font-size:22px;font-weight:750;letter-spacing:-.6px}.brand span{font-weight:350;color:var(--muted);margin-left:15px;font-size:16px}.tag{font:11px ui-monospace,monospace;border:1px solid #4c5c43;color:var(--green);padding:5px 8px;border-radius:4px}.top{display:flex;gap:18px;align-items:center}.wrap{max-width:1600px;margin:auto;padding:28px 34px}.heading{display:flex;align-items:end;justify-content:space-between;margin-bottom:20px}h1{font-size:28px;margin:0 0 7px;font-weight:620}h2{font-size:16px;margin:0}p{line-height:1.7;color:var(--muted);margin:8px 0}.grid{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:20px}.card{border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden}.cardhead{padding:17px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}.view{aspect-ratio:16/9;background:#050708;display:grid;place-items:center;position:relative;overflow:hidden}.view img{width:100%;height:100%;object-fit:contain;position:absolute}.overlay{position:absolute;top:16px;left:16px;z-index:2;background:#0009;padding:6px 10px;border-radius:4px;font:11px ui-monospace,monospace}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:6px}.rec{background:var(--red);animation:blink 2s infinite}@keyframes blink{50%{opacity:.3}}.viewfoot{display:flex;justify-content:space-between;padding:14px 20px;color:var(--muted);font-size:12px}.body{padding:20px}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}.metric{padding:17px 20px;background:var(--panel);border:1px solid var(--line);border-radius:10px}.metric small{color:var(--muted);display:block;margin-bottom:7px}.metric strong{font-size:22px;font-weight:550}.stack{display:flex;flex-direction:column;gap:20px}.joystick{touch-action:none;user-select:none;width:178px;height:178px;border-radius:50%;border:1px solid #4b5a61;margin:20px auto;background:radial-gradient(circle,#344044 0,#20272b 65%);position:relative;cursor:grab}.joystick:before,.joystick:after{content:"";position:absolute;background:#47565d}.joystick:before{width:1px;height:100%;left:50%}.joystick:after{height:1px;width:100%;top:50%}.knob{position:absolute;width:62px;height:62px;background:var(--green);border:7px solid #273321;border-radius:50%;left:57px;top:57px;box-shadow:0 3px 14px #0007;z-index:2}.axis{display:flex;justify-content:space-around;color:var(--muted);font-size:12px}.field{margin:12px 0}.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:7px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.section{margin-top:28px}.recordlist{max-height:390px;overflow:auto}.clip{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}.clip small{display:block;color:var(--muted);margin-top:4px}.clip button{padding:6px 10px}.progress{height:4px;background:#364247;margin-top:12px;border-radius:3px;overflow:hidden}.progress div{height:100%;background:var(--green);width:0}.hint{font-size:12px;line-height:1.65;color:var(--muted)}.status{font-size:12px;color:var(--green)}.error{color:var(--red)}.login{width:min(420px,90vw);margin:10vh auto;padding:30px}.hidden{display:none!important}.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#e8f2e1;color:#152018;padding:12px 22px;border-radius:8px;z-index:30;max-width:90vw}.modal{position:fixed;inset:0;background:#000c;z-index:20;display:grid;place-items:center;padding:24px}.modalbox{background:var(--panel);border:1px solid var(--line);max-width:1000px;width:100%;border-radius:12px;overflow:hidden}.modalbox img{width:100%;max-height:70vh;object-fit:contain;display:block}.log{font:11px ui-monospace,monospace;max-height:120px;overflow:auto;color:var(--muted)}@media(max-width:1000px){.grid{grid-template-columns:1fr}.stack{display:grid;grid-template-columns:1fr 1fr}}@media(max-width:650px){header{padding:0 18px;height:64px}.wrap{padding:22px 16px}.stack{display:flex}.brand span,.top .tag{display:none}.heading{align-items:start;gap:12px}h1{font-size:23px}.metrics{gap:7px}.metric{padding:12px}.metric strong{font-size:17px}.clip{padding:12px;flex-wrap:wrap}}
 .view video{position:absolute;width:100%;height:100%;object-fit:contain}.modalbox video{width:100%;max-height:65vh;display:block;background:#000}.viewfoot{flex-wrap:wrap;align-items:center;gap:8px}.viewfoot button{font-size:12px;padding:5px 10px}#playseek{padding:0;margin:12px 0 18px;accent-color:var(--green)}

/* Responsive reordering uses the same controls and event listeners. */
.camera-primary,.camera-sidebar{min-width:0}
.ptz-layout{display:grid;gap:14px}
.ptz-directions{justify-content:center}
.ptz-stop{width:100%;margin-top:12px;min-height:44px}
.joystick{width:var(--stick-size,178px);height:var(--stick-size,178px);-webkit-user-select:none;-webkit-touch-callout:none}
.knob{left:calc(50% - 31px);top:calc(50% - 31px);pointer-events:none}
@media(max-width:1000px){
 .grid{grid-template-columns:minmax(0,1fr);grid-template-areas:"live" "metrics" "ptz" "recordings" "status" "device" "wifi";gap:16px}
 .camera-primary,.camera-sidebar{display:contents}
 .live-card{grid-area:live}.metrics{grid-area:metrics;margin-top:0}
 .ptz-card{grid-area:ptz}.recordings-card{grid-area:recordings;margin-top:0}
 .status-card{grid-area:status;margin-top:0}.device-card{grid-area:device}.wifi-card{grid-area:wifi}
 .ptz-layout{grid-template-columns:minmax(132px,1fr) minmax(126px,1fr);align-items:center;gap:16px;max-width:560px;margin:auto}
 .ptz-pad{min-width:0;--stick-size:148px}
 .ptz-pad .joystick{margin:10px auto}
 .ptz-pad .axis{font-size:11px}
 .ptz-directions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));grid-template-areas:". up ." "left . right" ". down .";gap:5px}
 .ptz-directions button{min-height:44px;padding:6px 2px;touch-action:manipulation}
 #panLeft{grid-area:left}#tiltUp{grid-area:up}#panRight{grid-area:right}#tiltDown{grid-area:down}
 .ptz-actions{min-width:0}.ptz-stop{color:var(--green);border-color:#536448}
 .ptz-help{margin-top:10px}
}
@media(max-width:650px){
 header{padding:0 16px}.top{gap:8px}.top button{min-height:44px;padding:8px 10px;font-size:12px}
 .cardhead{padding:14px 16px;gap:10px;flex-wrap:wrap}.cardhead>.hint{font-size:10px}
 .body{padding:16px}.heading{flex-wrap:wrap}.heading .tag{font-size:10px}
 .ptz-card .body{padding:12px 14px}.ptz-layout{gap:12px}
 .ptz-help{display:none}.ptz-card #ptzFeedback{font-size:11px;margin-top:12px}
 .recordings-card .cardhead{align-items:flex-start;flex-direction:column}
 .recordings-card .cardhead>.row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;width:100%}
 .recordings-card .cardhead button{min-height:44px;padding:8px}
 .metric small{font-size:10px}.metric strong{font-size:16px}
 .clip>div{min-width:0}.clip small{overflow-wrap:anywhere}
}
@media(max-width:360px){
 .wrap{padding:18px 12px}.ptz-layout{grid-template-columns:minmax(120px,1fr) minmax(112px,1fr);gap:8px}
 .ptz-directions{grid-template-columns:repeat(2,minmax(0,1fr));grid-template-areas:"up down" "left right"}
 .ptz-pad{--stick-size:128px}.ptz-directions button{font-size:12px}.ptz-stop{font-size:12px}
 .metric{padding:10px 8px}.metric strong{font-size:14px}
}
.camera-picker{display:flex;align-items:center;gap:10px;margin-top:12px}.camera-picker select{width:auto;min-width:180px}.camera-picker label{color:var(--muted)}
@media(max-width:1000px){
 .grid.no-ptz{grid-template-areas:"live" "metrics" "recordings" "status" "device" "wifi"}
 .grid.no-wifi{grid-template-areas:"live" "metrics" "ptz" "recordings" "status" "device"}
 .grid.no-ptz.no-wifi{grid-template-areas:"live" "metrics" "recordings" "status" "device"}
}
</style>
<header><div class="brand">MuYu<span>Camera Console</span></div><div class="top"><span class="tag">LOCAL NETWORK</span><button id="rotateTotp" class="hidden">更换验证器</button><button id="logout" class="hidden">退出</button></div></header>
<div id="login" class="card login"><h1>连接你的摄像头</h1><p>请输入身份验证器当前显示的 6 位验证码</p><form id="loginform"><div class="field"><label>TOTP 动态验证码</label><input id="totpCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></div><button class="primary" style="width:100%;margin-top:12px">登录</button><p id="loginerror" class="error"></p></form></div>
<main id="app" class="wrap hidden"><div class="heading"><div><h1 id="cameraTitle">摄像头工作台</h1><p>实时查看、云台控制与服务器录像 · 两台摄像头独立录像</p><div class="camera-picker"><label for="cameraSelect">摄像头</label><select id="cameraSelect" disabled><option value="cam1">摄像头 1</option><option value="cam2">摄像头 2</option></select></div></div><span id="connection" class="tag">正在连接</span></div>
<div class="grid"><div class="camera-primary"><div class="card live-card"><div class="cardhead"><h2><span class="dot"></span>实时画面</h2><span id="codecLabel" class="hint">等待码流信息</span></div><div class="view"><span class="hint">正在等待摄像头画面…</span><video id="live" muted autoplay controls playsinline></video><div class="overlay"><span id="recDot" class="dot"></span><span id="recLabel">WAITING</span></div></div><div class="viewfoot"><span id="videoLabel">原码流录像 · 有声实时预览</span><button id="soundLive">开启实时声音</button><span id="liveStatus" class="hint"></span><span id="clock"></span></div></div>
<div class="metrics"><div class="metric"><small>服务器录像</small><strong id="recStatus">—</strong></div><div class="metric"><small>存储使用 / 32 GB</small><strong id="storage">—</strong><div class="progress"><div id="usagebar"></div></div></div><div class="metric"><small>录像分段</small><strong>10 <span class="hint">分钟 / 段</span></strong></div></div>
<section class="card section recordings-card"><div class="cardhead"><h2>录像档案 <small id="clipCount" class="hint"></small></h2><div class="row"><button id="toggleRec">暂停录像</button><button onclick="refresh()">刷新</button><button id="newerClips">较新</button><button id="olderClips">较旧</button></div></div><div class="body hint">原始视频与音频存储在服务器；到达容量上限前自动删除最旧已完成片段。当前片段关闭后可播放、下载。</div><div id="clips" class="recordlist"></div></section>
<section class="card section status-card"><div class="cardhead"><h2>运行状态</h2><a href="/" id="fallbackLink" class="hint">DNS 不可用？使用备用 IP</a></div><div class="body"><p id="deviceInfo" class="hint"></p><p id="serviceError" class="error"></p><div id="logs" class="log"></div></div></section></div>
<aside class="stack camera-sidebar"><section class="card ptz-card" aria-label="云台控制"><div class="cardhead"><h2>云台摇杆</h2><span class="hint">按住拖动 · 松手停止</span></div><div class="body"><div class="ptz-layout"><div class="ptz-pad"><div class="axis"><span>↑ 上</span><span>左右旋转</span></div><div id="stick" class="joystick" role="slider" aria-label="云台方向摇杆" tabindex="0"><div id="knob" class="knob"></div></div><div class="axis"><span>← 左</span><span>↓ 下</span><span>右 →</span></div></div><div class="ptz-actions"><div class="row ptz-directions"><button id="panLeft" aria-label="向左转动">← 左</button><button id="tiltUp" aria-label="向上转动">↑ 上</button><button id="tiltDown" aria-label="向下转动">↓ 下</button><button id="panRight" aria-label="向右转动">右 →</button></div><button id="stopPtz" class="ptz-stop">停止转动</button></div></div><p id="ptzFeedback" class="hint">垂直范围 -30°～85°；到限位后可反向移动。</p><p class="hint ptz-help">摇杆保持方向时连续转动，偏移越大速度越快；松手停止，失联约 1.2 秒自动停止。斜向优先偏移较大的轴。方向按钮为单步，方向键可持续控制。</p></div></section>
<section class="card device-card"><div class="cardhead"><h2>设备连接</h2><button id="discover">发现</button></div><div class="body"><div class="field"><label>设备识别方式</label><select id="mode"><option value="auto">自动发现 · MAC 绑定</option><option value="manual">手动指定 IP</option></select></div><div class="field"><label>摄像头 IP</label><input id="manualIp" placeholder="192.168.1.10"></div><button id="saveDevice" class="primary">保存连接</button><p id="binding" class="hint"></p><div id="candidates" class="hint"></div></div></section>
<section class="card wifi-card"><div class="cardhead"><h2>Wi-Fi 连接</h2><span class="hint">2.4 GHz</span></div><div class="body"><form id="wifiForm"><div class="field"><label>网络名称 SSID</label><input id="ssid" placeholder="输入无线网络名称" maxlength="32" required></div><div class="field"><label>Wi-Fi 密码</label><input id="wifiPassword" type="password" minlength="8" maxlength="63" autocomplete="new-password" required></div><button id="wifiSubmit" class="primary">测试并切换网络</button></form><p id="wifiStatus" class="hint"></p><p class="hint">切换需新网络能联系本服务器，失败自动回退。配置保存在服务器；断电后摄像头先连固件默认无线网络，或通过网线恢复联系，再自动下发。当前不改写摄像头固件。</p></div></section></aside></div></main>
<div id="playmodal" class="modal hidden"><div class="modalbox"><div class="cardhead"><h2 id="playtitle">录像回放</h2><button id="closeplay">关闭</button></div><video id="playvideo" controls playsinline preload="metadata"></video><div class="body"><p id="playmessage" class="hint">正在准备有声回放…</p><input id="playseek" type="range" min="0" max="600" step="0.1" value="0" aria-label="录像时间轴" disabled><div class="row" style="justify-content:space-between"><button id="back30">后退 30 秒</button><output id="playtime">00:00 / 10:00</output><button id="forward30">前进 30 秒</button></div></div></div></div><div id="totpmodal" class="modal hidden"><div class="modalbox"><div class="cardhead"><h2>更换身份验证器</h2><button id="closeTotp">关闭</button></div><div class="body"><p class="hint">请用新设备扫描二维码，或手动输入密钥；确认成功后旧设备和其他登录会话立即失效。</p><img id="totpQr" alt="TOTP二维码" style="display:block;width:260px;background:white;padding:12px;margin:18px auto"><p id="totpSecret" class="hint" style="word-break:break-all;text-align:center"></p><div class="field"><label>新设备当前 6 位验证码</label><input id="newTotpCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></div><button id="confirmTotp" class="primary" style="width:100%">确认更换</button><p id="totpError" class="error"></p></div></div></div><div id="toast" class="toast hidden"></div>
<script>
let csrf='',state={},poll,toastTimer,clipOffset=0;
const $=id=>document.getElementById(id);
let selectedCamera='cam1';try{const saved=sessionStorage.getItem('cameraId');if(['cam1','cam2'].includes(saved))selectedCamera=saved}catch(e){}
let cameraGeneration=0,refreshGeneration=0,cameras=[],switching=false,ready=false,refreshAbort=null;
const context=()=>({id:selectedCamera,generation:cameraGeneration});
const current=c=>c.id===selectedCamera&&c.generation===cameraGeneration;
function cameraURL(url,id){return url+(url.includes('?')?'&':'?')+'camera_id='+encodeURIComponent(id)}
function supports(cap,id=selectedCamera){return id!=='cam2'&&!!cameras.find(c=>c.id===id)?.capabilities?.[cap]}
function toast(t){$('toast').textContent=t;$('toast').classList.remove('hidden');clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').classList.add('hidden'),4500)}
async function api(url,data,signal){let r=await fetch(url,{method:data?'POST':'GET',headers:data?{'Content-Type':'application/json','X-CSRF-Token':csrf}:{},body:data?JSON.stringify(data):undefined,signal});let v=await r.json();if(!r.ok){if(r.status===401){ready=false;cameraGeneration++;stop();stopLive();closePlayback();$('app').classList.add('hidden');$('login').classList.remove('hidden');clearInterval(poll)}throw Error(v.detail||'操作失败')}return v}
function scoped(url,data,c=context(),signal){return api(cameraURL(url,c.id),data,signal)}
function node(tag,text,cls){let n=document.createElement(tag);n.textContent=text;if(cls)n.className=cls;return n}function formatBytes(n){return(n/1e9).toFixed(2)+' GB'}
function renderCameras(summary){if(summary)cameras=summary.filter(c=>['cam1','cam2'].includes(c.id));$('cameraSelect').replaceChildren(...cameras.map(c=>{let o=node('option',c.name||c.id);o.value=c.id;return o}));$('cameraSelect').value=selectedCamera;renderCapabilities()}
function renderCapabilities(){let ptz=supports('ptz'),wifi=supports('wifi');document.querySelector('.ptz-card').classList.toggle('hidden',!ptz);document.querySelector('.wifi-card').classList.toggle('hidden',!wifi);document.querySelector('.grid').classList.toggle('no-ptz',!ptz);document.querySelector('.grid').classList.toggle('no-wifi',!wifi);const cam=cameras.find(c=>c.id===selectedCamera);$('cameraTitle').textContent=cam?.name||selectedCamera}
function clearCameraView(){state={};clipOffset=0;$('clips').replaceChildren();$('candidates').replaceChildren();$('logs').replaceChildren();for(const id of ['connection','recStatus','storage','clipCount','binding','deviceInfo','serviceError','wifiStatus','ptzFeedback','liveStatus'])$(id).textContent='';$('codecLabel').textContent='等待码流信息';$('videoLabel').textContent='原码流录像 · 有声实时预览';$('manualIp').value='';$('manualIp').placeholder='摄像头 IP';$('mode').value='auto';$('wifiPassword').value='';$('usagebar').style.width='0%';$('recLabel').textContent='WAITING';$('recDot').className='dot';$('toggleRec').disabled=true;$('newerClips').disabled=true;$('olderClips').disabled=true;renderCapabilities()}
async function selectCamera(id){if(switching||!cameras.some(c=>c.id===id)||id===selectedCamera)return;switching=true;$('cameraSelect').disabled=true;const old=context();++cameraGeneration;++refreshGeneration;if(refreshAbort)refreshAbort.abort();stopLive();closePlayback();const moving=held||ptzBusy||stepActive;resetPtz();try{if(moving)await motorRequest(0,0,'continuous',old,true)}catch(e){toast(e.message)}finally{selectedCamera=id;try{sessionStorage.setItem('cameraId',id)}catch(e){}switching=false;$('cameraSelect').disabled=false;$('cameraSelect').value=id;clearCameraView();await refresh()}}
$('cameraSelect').onchange=e=>selectCamera(e.target.value);
async function refresh(){if(switching||!ready)return;const c=context(),generation=++refreshGeneration,offset=clipOffset;if(refreshAbort)refreshAbort.abort();const controller=new AbortController();refreshAbort=controller;try{let s=await scoped('/api/state?offset='+offset,undefined,c,controller.signal);if(!current(c)||generation!==refreshGeneration||s.camera_id&&s.camera_id!==c.id)return;state=s;if(s.cameras)renderCameras(s.cameras);const cam=cameras.find(cam=>cam.id===c.id);if(cam){if(s.capabilities)cam.capabilities=s.capabilities;if(s.camera_name)cam.name=s.camera_name;renderCapabilities()}
$('newerClips').disabled=offset===0;$('olderClips').disabled=!s.recordings_has_more;if(s.csrf)csrf=s.csrf;$('connection').textContent=s.online?'在线 · '+s.ip:'等待设备';$('recStatus').textContent=s.recording?'正在录制':s.recording_enabled?'等待信号':'已暂停';$('storage').textContent=formatBytes(s.storage_bytes);$('usagebar').style.width=(s.storage_bytes/s.storage_limit_bytes*100)+'%';$('recLabel').textContent=s.recording?'REC · SERVER':'LIVE';$('recDot').className='dot'+(s.recording?' rec':'');$('toggleRec').disabled=false;$('toggleRec').textContent=s.recording_enabled?'暂停录像':'开始录像';$('clipCount').textContent='· '+s.total_recordings+' 段';$('binding').textContent='绑定 MAC '+(s.identity_mac||'—');const codec=s.video_codec||'原码流',resolution=s.video_resolution||'';$('codecLabel').textContent=[s.camera_name||cam?.name||c.id,codec,resolution].filter(Boolean).join(' · ');$('videoLabel').textContent=[resolution,'原码流录像 · 有声实时预览'].filter(Boolean).join(' · ');$('fallbackLink').href=s.fallback_url||'/';$('deviceInfo').textContent='摄像头 '+(s.ip||'未发现')+' · 录像 MKV / '+codec+' · '+(s.server_url||'');$('serviceError').textContent=[s.error,s.recording_error,s.ptz_error].filter(Boolean).join(' / ');$('wifiStatus').textContent=s.wifi?.message||'';$('wifiSubmit').disabled=!supports('wifi')||s.wifi?.state==='switching';if(document.activeElement!==$('mode'))$('mode').value=s.mode;if(document.activeElement!==$('manualIp'))$('manualIp').value=s.manual_ip||s.ip||'';$('candidates').replaceChildren(...(s.candidates||[]).map(c=>node('p',c.ip+' · '+c.model+(c.bound_match?' · 已绑定':''))));$('logs').replaceChildren(...(s.logs||[]).slice(-8).reverse().map(l=>node('div',l.time+'  '+l.text)));$('clips').replaceChildren(...(s.recordings||[]).map(clip=>{let row=node('div','','clip'),d=node('div',new Date(clip.mtime*1000).toLocaleString('zh-CN'));d.append(node('small',(clip.bytes/1e6).toFixed(1)+' MB · '+(clip.active?'录制中':clip.name)));let actions=node('div','','row');if(!clip.active){let b=node('button','播放');b.onclick=()=>{if(current(c))play(clip.name,c)};let a=node('a','下载');a.href=cameraURL('/api/recordings/'+encodeURIComponent(clip.name),c.id);actions.append(b,a)}row.append(d,actions);return row}));if(s.online&&!liveRunning)startLive(c);else if(!s.online)stopLive()}catch(e){if(current(c)&&generation===refreshGeneration&&e.name!=='AbortError')toast(e.message)}}
$('newerClips').onclick=()=>{clipOffset=Math.max(0,clipOffset-100);refresh()};$('olderClips').onclick=()=>{clipOffset+=100;refresh()};
async function enter(){let r=await api('/api/cameras');if(r.csrf)csrf=r.csrf;renderCameras(r.cameras);if(!cameras.some(c=>c.id===selectedCamera))selectedCamera=cameras[0]?.id||'cam1';$('cameraSelect').value=selectedCamera;ready=true;clearCameraView();$('cameraSelect').disabled=false;$('login').classList.add('hidden');$('app').classList.remove('hidden');$('logout').classList.remove('hidden');$('rotateTotp').classList.remove('hidden');await refresh();clearInterval(poll);poll=setInterval(refresh,6000)}
$('loginform').onsubmit=async e=>{e.preventDefault();try{await api('/api/login',{code:$('totpCode').value});$('totpCode').value='';await enter()}catch(e){$('loginerror').textContent=e.message}};
$('logout').onclick=async()=>{await api('/api/logout',{});location.reload()};
async function control(url,data,message,cap){if(!ready||switching||cap&&!supports(cap))return;const c=context();try{await scoped(url,data,c);if(!current(c))return;if(url==='/api/wifi')$('wifiPassword').value='';toast(message);refresh();if(url==='/api/recording')setTimeout(()=>{if(current(c))refresh()},1500)}catch(e){if(current(c))toast(e.message)}}
$('discover').onclick=()=>control('/api/discover',{},'正在扫描局域网');$('saveDevice').onclick=()=>control('/api/device',{mode:$('mode').value,ip:$('manualIp').value},'连接配置已保存');$('toggleRec').onclick=()=>{if(state.camera_id&&state.camera_id!==selectedCamera||!Object.keys(state).length)return;control('/api/recording',{enabled:!state.recording_enabled},'录像设置已保存')};$('wifiForm').onsubmit=e=>{e.preventDefault();control('/api/wifi',{ssid:$('ssid').value,password:$('wifiPassword').value},'已开始测试 Wi-Fi，连接确认前会保留回退','wifi')};
function showTotpModal(value){$('totpQr').src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(value.qr_svg);$('totpSecret').textContent='手动密钥：'+value.secret;$('newTotpCode').value='';$('totpError').textContent='';$('totpmodal').classList.remove('hidden')}
$('closeTotp').onclick=()=>{$('totpmodal').classList.add('hidden')};$('rotateTotp').onclick=async()=>{let code=prompt('请输入当前身份验证器的6位验证码');if(!code)return;try{showTotpModal(await api('/api/auth/rotate/start',{code}))}catch(e){toast(e.message)}};$('confirmTotp').onclick=async()=>{try{await api('/api/auth/rotate/confirm',{code:$('newTotpCode').value});location.reload()}catch(e){$('totpError').textContent=e.message}};

let held=false,vx=0,vy=0,ptzBusy=false,controlSeq=0,heldContext=null,stepActive=false,stepTimer=null;
const controlId=Array.from(crypto.getRandomValues(new Uint8Array(12)),b=>b.toString(16).padStart(2,'0')).join('');
function resetPtz(){held=false;heldContext=null;vx=vy=0;stepActive=false;clearTimeout(stepTimer);$('knob').style.transform=''}
async function motorRequest(x,y,mode='continuous',c=context(),forceStop=false){if(!(forceStop&&x===0&&y===0)&&(!current(c)||switching||!ready||!supports('ptz',c.id)))return;let r=await scoped('/api/ptz',{x,y,mode,control_id:controlId,sequence:++controlSeq},c);if(current(c)&&r.message)$('ptzFeedback').textContent=r.message;return r}
async function sendPtz(){if(ptzBusy||!held||!heldContext||!current(heldContext)||switching||!supports('ptz'))return;const c=heldContext;ptzBusy=true;try{await motorRequest(vx,vy,'continuous',c)}catch(e){if(current(c)){toast(e.message);resetPtz()}}finally{ptzBusy=false;if(!held||!current(c))motorRequest(0,0,'continuous',c,true).catch(()=>{})}}
function stop(){const c=heldContext||context(),moving=held||stepActive;resetPtz();if(moving||ready&&!switching&&supports('ptz'))motorRequest(0,0,'continuous',c,true).catch(e=>{if(current(c))toast(e.message)})}
let stick=$('stick');function drag(e){let r=stick.getBoundingClientRect(),radius=Math.max(1,(r.width-62)/2),travel=Math.max(0,radius-6),x=(e.clientX-r.left-r.width/2)/radius,y=(r.top+r.height/2-e.clientY)/radius,l=Math.hypot(x,y);if(l>1){x/=l;y/=l}vx=x*.65;vy=y*.65;$('knob').style.transform=`translate(${x*travel}px,${-y*travel}px)`}
stick.onpointerdown=e=>{if(switching||!ready||!supports('ptz'))return;e.preventDefault();stick.setPointerCapture(e.pointerId);heldContext=context();held=true;drag(e);sendPtz()};stick.onpointermove=e=>{if(held&&heldContext&&current(heldContext))drag(e)};stick.onpointerup=stop;stick.onpointercancel=stop;stick.onlostpointercapture=()=>{if(held)stop()};$('stopPtz').onclick=stop;window.addEventListener('blur',()=>{if(held)stop()});document.addEventListener('visibilitychange',()=>{if(document.hidden&&held)stop()});setInterval(sendPtz,180);stick.onkeydown=e=>{if(switching||!ready||!supports('ptz'))return;let d={ArrowLeft:[-.35,0],ArrowRight:[.35,0],ArrowUp:[0,.35],ArrowDown:[0,-.35]}[e.key];if(d){e.preventDefault();heldContext=context();held=true;[vx,vy]=d;sendPtz()}};stick.onkeyup=e=>{if(e.key.startsWith('Arrow'))stop()};
for(let [id,x,y] of [['panLeft',-.5,0],['panRight',.5,0],['tiltUp',0,.5],['tiltDown',0,-.5]]){$(id).onclick=async()=>{if(switching||!ready||!supports('ptz'))return;const c=context();stepActive=true;try{await motorRequest(x,y,'step',c);if(!current(c))return;clearTimeout(stepTimer);stepTimer=setTimeout(()=>{stepActive=false;if(!held&&current(c))motorRequest(0,0,'continuous',c,true).catch(()=>{})},550)}catch(e){if(current(c))toast(e.message)}}}
let liveRunning=false,liveAbort=null,liveSound=false,liveGeneration=0,liveRetry=null,liveObjectURL=null,liveReader=null;
$('soundLive').onclick=()=>{const c=context();let v=$('live');liveSound=!liveSound;v.muted=!liveSound;v.volume=1;v.play().catch(()=>{if(current(c))toast('请点击播放器中的播放按钮')});$('soundLive').textContent=liveSound?'静音实时声音':'开启实时声音'};
function stopLive(){++liveGeneration;clearTimeout(liveRetry);if(liveAbort)liveAbort.abort();liveAbort=null;if(liveReader)liveReader.cancel().catch(()=>{});liveReader=null;liveRunning=false;const v=$('live');v.onprogress=v.onerror=null;v.pause();v.removeAttribute('src');v.load();if(liveObjectURL)URL.revokeObjectURL(liveObjectURL);liveObjectURL=null}
function waitEvent(target,event,signal,action){return new Promise((resolve,reject)=>{const clean=()=>{target.removeEventListener(event,done);target.removeEventListener('error',bad);signal.removeEventListener('abort',abort)};const done=()=>{clean();resolve()};const bad=()=>{clean();reject(Error('视频缓冲失败'))};const abort=()=>{clean();reject(new DOMException('Aborted','AbortError'))};if(signal.aborted){abort();return}target.addEventListener(event,done,{once:true});target.addEventListener('error',bad,{once:true});signal.addEventListener('abort',abort,{once:true});if(action)try{action()}catch(e){clean();reject(e)}})}
async function startLive(c=context()){
 if(liveRunning||!current(c)||switching||!ready)return;liveRunning=true;const generation=++liveGeneration,controller=new AbortController(),signal=controller.signal,v=$('live');liveAbort=controller;let objectURL=null,reader=null,nativeMode=false;
 const valid=()=>!signal.aborted&&current(c)&&generation===liveGeneration;
 const retry=()=>{if(!valid())return;stopLive();if(current(c)&&state.online&&ready)liveRetry=setTimeout(()=>{if(current(c))startLive(c)},2000)};
 try{
  v.muted=!liveSound;v.volume=1;const mime='video/mp4; codecs="avc1.42c01f,mp4a.40.2"';
  if(!window.MediaSource||!MediaSource.isTypeSupported(mime)){nativeMode=true;v.src=cameraURL('/api/live',c.id);v.onprogress=()=>{if(valid()&&v.buffered.length&&!v.paused&&v.buffered.end(v.buffered.length-1)-v.currentTime>4)v.currentTime=v.buffered.end(v.buffered.length-1)-.5};v.onerror=retry;v.play().catch(()=>{});$('liveStatus').textContent='实时音视频';return}
  const media=new MediaSource();objectURL=URL.createObjectURL(media);liveObjectURL=objectURL;const opened=waitEvent(media,'sourceopen',signal);v.src=objectURL;await opened;if(!valid())return;
  const buffer=media.addSourceBuffer(mime);const response=await fetch(cameraURL('/api/live',c.id),{signal});if(!valid())return;if(!response.ok)throw Error('实时流暂时不可用');reader=response.body.getReader();liveReader=reader;let started=false;
  async function update(action){await waitEvent(buffer,'updateend',signal,action)}
  while(valid()){let timer,item;try{item=await Promise.race([reader.read(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('实时流重新连接中')),15000)})])}finally{clearTimeout(timer)}if(!valid()||item.done)break;await update(()=>buffer.appendBuffer(item.value));if(!valid())return;if(buffer.buffered.length){let begin=buffer.buffered.start(0),end=buffer.buffered.end(buffer.buffered.length-1);if(!started||(!v.paused&&(v.currentTime<begin||end-v.currentTime>4)))v.currentTime=Math.max(begin,end-.5);if(!started){started=true;v.play().catch(()=>{});$('liveStatus').textContent='实时音视频'}if(end-begin>25)await update(()=>buffer.remove(begin,end-20))}}
 }catch(e){if(valid())$('liveStatus').textContent='重新连接中…'}finally{if(!nativeMode){if(reader)reader.cancel().catch(()=>{});if(objectURL)URL.revokeObjectURL(objectURL);if(valid())retry()}}
}

let playGeneration=0,playDragging=false,liveBeforePlayback=true,playSession=null,playAbort=null,playObjectURL=null,playSwitching=false,nativePlay=false,playOffset=0,playCacheTimer=null,playSeekTimer=null,playRetryTimer=null;
function timeLabel(value){value=Math.max(0,Math.floor(value||0));return String(Math.floor(value/60)).padStart(2,'0')+':'+String(value%60).padStart(2,'0')}
function absolutePlayTime(){return $('playvideo').currentTime+(nativePlay?playOffset:0)}
function syncPlayTime(){if(!playSession)return;let duration=playSession.duration||0;if(duration){if(!playDragging)$('playseek').value=absolutePlayTime();$('playseek').max=duration;$('playseek').disabled=false;$('playtime').textContent=timeLabel(absolutePlayTime())+' / '+timeLabel(duration)}}
function isPlayBuffered(target){let v=$('playvideo'),t=target-(nativePlay?playOffset:0);for(let i=0;i<v.buffered.length;i++){if(t>=v.buffered.start(i)-.02&&t<v.buffered.end(i)-.05)return true}return false}
async function loadPlayStream(start,autoplay=true,retries=0){
 if(!playSession||!current(playSession.camera))return;const session=playSession,generation=++playGeneration;playSwitching=true;session.failed=false;clearTimeout(playRetryTimer);if(playAbort)playAbort.abort();const controller=new AbortController();playAbort=controller;const signal=controller.signal;const valid=()=>!signal.aborted&&generation===playGeneration&&playSession===session&&current(session.camera);let v=$('playvideo');v.pause();if(playObjectURL){URL.revokeObjectURL(playObjectURL);playObjectURL=null}v.removeAttribute('src');v.load();v.muted=false;v.volume=1;playOffset=start;
 $('playmessage').textContent='正在连接 '+timeLabel(start)+'，首批片段生成后立即播放…';
 const mime='video/mp4; codecs="avc1.42c01f,mp4a.40.2"';
 try{
  nativePlay=!window.MediaSource||!MediaSource.isTypeSupported(mime);
  if(nativePlay){v.src=cameraURL('/api/play/'+encodeURIComponent(session.name)+'/stream?start='+start,session.camera.id);playSwitching=false;if(autoplay)v.play().catch(()=>{});return}
  const media=new MediaSource();playObjectURL=URL.createObjectURL(media);v.src=playObjectURL;
  await new Promise((resolve,reject)=>{media.addEventListener('sourceopen',resolve,{once:true});signal.addEventListener('abort',()=>reject(new DOMException('Aborted','AbortError')),{once:true})});
  if(!valid())return;media.duration=session.duration;const buffer=media.addSourceBuffer(mime);buffer.timestampOffset=start;
  const response=await fetch(cameraURL('/api/play/'+encodeURIComponent(session.name)+'/stream?start='+start,session.camera.id),{signal});if(!valid())return;if(!response.ok)throw Error(response.status===429?'回放切换中，请稍候':'回放连接暂时不可用');const reader=response.body.getReader();signal.addEventListener('abort',()=>{reader.cancel().catch(()=>{})},{once:true});let first=true;
  async function update(action){await waitEvent(buffer,'updateend',signal,action)}
  while(valid()){
   if(!first&&v.buffered.length&&v.buffered.end(v.buffered.length-1)-v.currentTime>90){await new Promise(r=>setTimeout(r,200));continue}
   const item=await reader.read();if(!valid()||item.done)break;await update(()=>buffer.appendBuffer(item.value));if(!valid())return;
   if(buffer.buffered.length){
    if(first){first=false;v.currentTime=Math.max(start,buffer.buffered.start(0)+.001);playSwitching=false;if(autoplay)v.play().catch(()=>{if(valid())$('playmessage').textContent='已收到音视频，请点击播放按钮'});syncPlayTime()}
    if(!playSwitching&&v.currentTime-buffer.buffered.start(0)>40){await update(()=>buffer.remove(buffer.buffered.start(0),v.currentTime-25))}
   }
  }
  if(valid()&&media.readyState==='open'&&!buffer.updating){media.endOfStream();media.duration=session.duration}
 }catch(e){if(valid()){session.failed=true;playSwitching=false;$('playmessage').textContent='回放重新连接中…';if(retries<2)playRetryTimer=setTimeout(()=>{if(valid())loadPlayStream(Math.max(start,absolutePlayTime()),autoplay,retries+1)},500);else $('playmessage').textContent='回放连接失败，请关闭后重试'}}
}
function seekPlayback(target){if(!playSession)return;target=Math.max(0,Math.min(playSession.duration-.25,Number(target)));let v=$('playvideo');if(isPlayBuffered(target)){v.currentTime=target-(nativePlay?playOffset:0)}else{loadPlayStream(target,!v.paused)}playDragging=false;syncPlayTime()}
async function play(name,c=context()){
 if(!current(c)||switching||!ready)return;closePlayback();
 if(playCacheTimer)clearInterval(playCacheTimer);const session={name,camera:c,duration:0,failed:false};playSession=session;$('playmodal').classList.remove('hidden');$('playtitle').textContent=name;$('playseek').disabled=true;$('playseek').value=0;$('playmessage').textContent='正在读取录像信息…';liveBeforePlayback=$('live').muted;$('live').muted=true;
 try{const job=await scoped('/api/playback/'+encodeURIComponent(name)+'/prepare',{},c);if(playSession!==session||!current(c))return;session.duration=job.duration;syncPlayTime();loadPlayStream(0,true);
 playCacheTimer=setInterval(async()=>{if(playSession!==session||!current(c))return;try{let j=await scoped('/api/playback/'+encodeURIComponent(name)+'/status',undefined,c);if(playSession!==session||!current(c))return;if(j.state==='not-prepared')j=await scoped('/api/playback/'+encodeURIComponent(name)+'/prepare',{},c);if(playSession!==session||!current(c))return;if(!session.failed&&!playSwitching)$('playmessage').textContent=j.state==='ready'?'有声回放 · 已缓存，可直接拖动时间轴':'有声回放 · 边播边缓存 '+(j.progress||0)+'% · 可随时跳转'}catch(e){}},1500)
 }catch(e){if(playSession===session&&current(c))$('playmessage').textContent=e.message}
}
$('playvideo').onloadedmetadata=syncPlayTime;$('playvideo').ontimeupdate=syncPlayTime;$('playvideo').onseeked=syncPlayTime;
$('playvideo').onseeking=()=>{if(playSession&&!nativePlay&&!playSwitching&&!isPlayBuffered($('playvideo').currentTime)){const session=playSession,generation=playGeneration,target=$('playvideo').currentTime,autoplay=!$('playvideo').paused;clearTimeout(playSeekTimer);playSeekTimer=setTimeout(()=>{if(playSession===session&&generation===playGeneration&&current(session.camera)&&!playSwitching)loadPlayStream(target,autoplay)},120)}};
$('playseek').oninput=()=>{playDragging=true;$('playtime').textContent=timeLabel($('playseek').value)+' / '+timeLabel(playSession?.duration)};$('playseek').onchange=()=>seekPlayback($('playseek').value);$('back30').onclick=()=>seekPlayback(absolutePlayTime()-30);$('forward30').onclick=()=>seekPlayback(absolutePlayTime()+30);
function closePlayback(){const wasPlaying=!!playSession;++playGeneration;playSession=null;playDragging=false;playSwitching=false;if(playAbort)playAbort.abort();clearInterval(playCacheTimer);clearTimeout(playSeekTimer);clearTimeout(playRetryTimer);let v=$('playvideo');v.pause();v.removeAttribute('src');v.load();if(playObjectURL)URL.revokeObjectURL(playObjectURL);playObjectURL=null;$('playmodal').classList.add('hidden');$('live').muted=liveBeforePlayback}
$('closeplay').onclick=closePlayback;
setInterval(()=>$('clock').textContent=new Date().toLocaleTimeString('zh-CN'),1000);enter().catch(()=>{});
</script></html>'''

BIND_HTML = r'''<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>MuYu · 绑定身份验证器</title><style>body{margin:0;background:#101315;color:#eef3f5;font:15px system-ui,Microsoft YaHei,sans-serif}.card{width:min(520px,92vw);margin:8vh auto;padding:28px;background:#191e21;border:1px solid #30383d;border-radius:12px}input,button{font:inherit;width:100%;padding:11px;margin-top:9px;box-sizing:border-box}input{background:#101518;color:#fff;border:1px solid #3a454c;border-radius:6px}button{background:#b6ed7d;border:0;border-radius:6px;font-weight:650}.error{color:#f38d80}.hint{color:#98a6ad;line-height:1.7}#qr{display:block;width:280px;background:#fff;padding:12px;margin:20px auto}#secret{word-break:break-all;text-align:center}</style><main class='card'><h1>绑定 TOTP 身份验证器</h1><p class='hint'>此页面需要服务器本地 CLI 生成的一次性授权。请用 Aegis、Google Authenticator 或 2FAS 扫描二维码。</p><button id='start'>开始绑定</button><section id='setup' hidden><img id='qr' alt='TOTP二维码'><p id='secret' class='hint'></p><label>输入身份验证器显示的 6 位验证码</label><input id='code' inputmode='numeric' pattern='[0-9]{6}' maxlength='6' autocomplete='one-time-code'><button id='confirm'>确认绑定</button></section><p id='message' class='error'></p></main><script>const token=decodeURIComponent(location.hash.slice(1)).replace(/^token=/,'');const $=id=>document.getElementById(id);$('start').onclick=async()=>{try{let r=await fetch('/api/auth/bind/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});let v=await r.json();if(!r.ok)throw Error(v.detail||'授权无效');$('qr').src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(v.qr_svg);$('secret').textContent='手动密钥：'+v.secret;$('setup').hidden=false;$('start').disabled=true}catch(e){$('message').textContent=e.message}};$('confirm').onclick=async()=>{try{let r=await fetch('/api/auth/bind/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,code:$('code').value})});let v=await r.json();if(!r.ok)throw Error(v.detail||'验证码错误');$('message').className='hint';$('message').textContent='绑定成功，请返回登录页面。';$('confirm').disabled=true}catch(e){$('message').textContent=e.message}};</script></html>'''



def build_app(m):
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
    # Request must be resolvable for FastAPI's annotation inspection.
    globals()['Request'] = Request

    class PinnedFileResponse(FileResponse):
        """Hold the exact file across Range reads, cancellation and quota pruning."""
        def __init__(self, path, camera, **kwargs):
            self.hub, self.pinned_path = camera.hub, path
            if self.hub:
                with self.hub.storage_lock:
                    if not path.is_file():
                        raise HTTPException(404,'文件已被容量轮转清理')
                    self.hub.pin(path)
            super().__init__(path, **kwargs)

        async def __call__(self, scope, receive, send):
            try:
                await super().__call__(scope, receive, send)
            finally:
                if self.hub:
                    self.hub.unpin(self.pinned_path)

    @asynccontextmanager
    async def lifespan(app):
        worker = threading.Thread(target=m.run, daemon=True)
        watchdog = threading.Thread(target=m.ptz_watchdog, daemon=True)
        worker.start()
        watchdog.start()
        yield
        m.stop.set()
        try:
            if hasattr(m,'shutdown_controls'):
                await asyncio.to_thread(m.shutdown_controls)
            elif m.ip:
                await asyncio.to_thread(m.ptz, 0, 0)
        except Exception:
            pass
        await asyncio.to_thread(worker.join, 12)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def request_scheme(request: Request) -> str:
        peer = request.client.host if request.client else ''
        trusted = {x.strip() for x in os.environ.get(
            'CAM_TRUSTED_PROXIES', '127.0.0.1,::1').split(',') if x.strip()}
        forwarded = request.headers.get('x-forwarded-proto', '').split(',')[0].strip().lower()
        if peer in trusted and forwarded in ('http', 'https'):
            return forwarded
        return request.url.scheme

    def secure_cookie(request: Request) -> bool:
        return request_scheme(request) == 'https'

    def auth_error(exc: AuthError) -> JSONResponse:
        response = JSONResponse({'detail': exc.detail}, status_code=exc.status)
        response.headers['Cache-Control'] = 'no-store'
        if exc.retry_after is not None:
            response.headers['Retry-After'] = str(exc.retry_after)
        return response

    @app.exception_handler(AuthError)
    async def handle_auth_error(request: Request, exc: AuthError):
        return auth_error(exc)

    @app.middleware('http')
    async def auth(request: Request, call_next):
        path = request.url.path
        raw_session = request.cookies.get('cam_session', '')
        try:
            session = m.auth.session(raw_session)
        except AuthError as exc:
            return auth_error(exc)
        public_api = {
            '/api/login', '/api/auth/status', '/api/auth/bind/start',
            '/api/auth/bind/confirm',
        }
        if path.startswith('/api/') and path not in public_api:
            if not session or session['expires_at'] < time.time():
                return JSONResponse({'detail': '请先登录管理台'}, status_code=401)
            request.state.session = session
            if request.method != 'GET' and not hmac.compare_digest(request.headers.get('x-csrf-token', ''), session['csrf']):
                return JSONResponse({'detail': '页面已失效，请刷新'}, status_code=403)
            global_paths = {'/api/logout', '/api/cameras', '/api/auth/rotate/start', '/api/auth/rotate/confirm'}
            if path not in global_paths:
                if hasattr(m,'managers'):
                    ids = request.query_params.getlist('camera_id')
                    if len(ids) != 1:
                        return JSONResponse({'detail':'请明确指定一个camera_id'},status_code=400)
                    selected = m.managers.get(ids[0])
                    if selected is None:
                        return JSONResponse({'detail':'摄像头不存在'},status_code=404)
                    request.state.camera = selected
                else:
                    request.state.camera = m
        if request.method == 'POST':
            origin = request.headers.get('origin')
            if origin and not origin_allowed(origin,request.headers.get('host',''),request.url.scheme):
                return JSONResponse({'detail': '不允许的请求来源'}, status_code=403)
            try:
                if int(request.headers.get('content-length', '0')) > 8192:
                    return JSONResponse({'detail': '请求太大'}, status_code=413)
            except ValueError:
                return JSONResponse({'detail': '无效长度'}, status_code=400)
        response = await call_next(request)
        if (session and raw_session and response.status_code < 400
                and m.auth.should_slide(request.method, path)):
            try:
                refreshed = m.auth.slide(raw_session)
            except AuthError as exc:
                return auth_error(exc)
            if refreshed:
                response.set_cookie(
                    'cam_session', raw_session, max_age=m.auth.session_ttl,
                    httponly=True, samesite='strict', secure=secure_cookie(request),
                    path='/',
                )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store'
        if path == '/api/live' or (path.startswith('/api/play/') and path.endswith('/stream')):
            response.headers['X-Accel-Buffering'] = 'no'
            response.headers['Cache-Control'] = 'no-store, no-transform'
        return response

    @app.get('/')
    def index():
        return HTMLResponse(HTML)

    @app.get('/bind')
    def bind_page():
        return HTMLResponse(BIND_HTML)

    @app.get('/api/auth/status')
    def auth_status():
        return m.auth.public_status()

    @app.get('/api/cameras')
    def cameras(request: Request):
        return {'cameras':m.cameras(),'csrf':request.state.session['csrf']}

    @app.post('/api/login')
    async def login(request: Request):
        body = await request.json()
        try:
            token, csrf, expires = m.auth.login(
                body.get('code', ''), request.client.host if request.client else 'unknown')
        except AuthError as exc:
            return auth_error(exc)
        response = JSONResponse({'ok': True, 'expires_at': expires, 'csrf': csrf})
        response.set_cookie(
            'cam_session', token, httponly=True, samesite='strict',
            secure=secure_cookie(request), max_age=max(0, expires - int(time.time())), path='/',
        )
        return response

    @app.post('/api/logout')
    def logout(request: Request):
        m.auth.logout(request.cookies.get('cam_session', ''))
        response = JSONResponse({'ok': True})
        response.delete_cookie('cam_session', path='/')
        return response

    @app.post('/api/auth/bind/start')
    async def bind_start(request: Request):
        try:
            body = await request.json()
            return m.auth.begin_binding(str(body.get('token', '')))
        except AuthError as exc:
            return auth_error(exc)

    @app.post('/api/auth/bind/confirm')
    async def bind_confirm(request: Request):
        try:
            body = await request.json()
            m.auth.confirm_binding(str(body.get('token', '')), body.get('code', ''))
            return {'ok': True}
        except AuthError as exc:
            return auth_error(exc)

    @app.post('/api/auth/rotate/start')
    async def rotate_start(request: Request):
        try:
            body = await request.json()
            return m.auth.rotate_start(
                body.get('code', ''), request.cookies.get('cam_session', ''))
        except AuthError as exc:
            return auth_error(exc)

    @app.post('/api/auth/rotate/confirm')
    async def rotate_confirm(request: Request):
        try:
            body = await request.json()
            m.auth.rotate_confirm(body.get('code', ''), request.cookies.get('cam_session', ''))
            response = JSONResponse({'ok': True})
            response.delete_cookie('cam_session', path='/')
            return response
        except AuthError as exc:
            return auth_error(exc)

    @app.get('/api/state')
    def state(request: Request, offset: int = 0):
        m = request.state.camera
        if offset < 0 or offset > 100000:
            raise HTTPException(400, '无效录像页码')
        return {**m.state(offset), 'csrf': request.state.session['csrf'],
                'server_url':str(request.base_url).rstrip('/')}

    @app.post('/api/discover')
    def discover(request: Request):
        m = request.state.camera
        m.wakeup.set()
        return {'ok': True}

    @app.post('/api/device')
    async def device(request: Request):
        m = request.state.camera
        body = await request.json()
        if body.get('mode') not in ('auto', 'manual'):
            raise HTTPException(400, '无效模式')
        try:
            ip = lan_ip(body.get('ip', ''))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        with m.lock:
            m.cfg.update(mode=body['mode'], manual_ip=ip)
            m.save()
            m.ip = None
            m.camera = {}
        m.wakeup.set()
        return {'ok': True}

    @app.post('/api/recording')
    async def recording(request: Request):
        m = request.state.camera
        body = await request.json()
        if type(body.get('enabled')) is not bool:
            raise HTTPException(400, 'enabled 应为布尔值')
        m.cfg['recording'] = body['enabled']
        m.save()
        return {'ok': True}

    @app.post('/api/ptz')
    async def ptz(request: Request):
        m = request.state.camera
        if not m.capabilities['ptz']:
            raise HTTPException(409,'该摄像头未开放云台控制')
        body = await request.json()
        try:
            control_id = body.get('control_id','')
            if not isinstance(control_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{0,64}',control_id):
                raise ValueError('无效控制标识')
            return await asyncio.to_thread(m.ptz, body.get('x', 0), body.get('y', 0),
                body.get('sequence'), request.state.session['csrf']+':'+control_id, body.get('mode','continuous'))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except Exception as exc:
            m.ptz_error = str(exc) if isinstance(exc,RuntimeError) else '摄像头控制连接暂时不可用，请重试'
            raise HTTPException(502, m.ptz_error)

    @app.post('/api/wifi')
    async def wifi(request: Request):
        m = request.state.camera
        if not m.capabilities['wifi']:
            raise HTTPException(409,'该摄像头未开放Wi-Fi配置')
        body = await request.json()
        ssid, password = body.get('ssid', ''), body.get('password', '')
        if not isinstance(ssid, str) or not isinstance(password, str) or not (1 <= len(ssid.encode()) <= 32) or not (8 <= len(password) <= 63) or not password.isascii():
            raise HTTPException(400, 'SSID 应为 1–32 字节；WPA2 密码应为 8–63 位 ASCII 字符')
        psk = hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32).hex()
        config = 'ctrl_interface=/tmp/wpa_supplicant\nupdate_config=0\nnetwork={\n ssid=' + ssid.encode().hex() + '\n psk=' + psk + '\n key_mgmt=WPA-PSK\n}\n'
        try:
            m.start_wifi(dict(ssid=ssid, config=config, md5=hashlib.md5(config.encode()).hexdigest()))
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return {'ok': True, 'rollback_seconds': 60, 'persistent_on_camera': False}

    @app.get('/api/live')
    async def live(request: Request):
        m = request.state.camera
        async def frames():
            if m.hub:
                m.hub.select_preview(m)
            try:
                async for fragment in stream_frames():
                    yield fragment
            finally:
                if m.hub:
                    m.hub.release_preview(m)

        async def stream_frames():
            seq = -1
            generation = None
            next_auth_check = 0
            while not m.stop.is_set():
                if time.monotonic() >= next_auth_check:
                    try:
                        valid = m.auth.session(request.cookies.get('cam_session',''))
                    except AuthError:
                        break
                    if not valid:
                        break
                    next_auth_check = time.monotonic()+2
                m.preview_seen = time.time()
                with m.preview_lock:
                    init, fragments, gen = m.mp4_init, list(m.mp4_fragments), m.preview_generation
                if generation is not None and gen != generation:
                    break
                if generation is None and init and fragments:
                    generation = gen
                    seq = fragments[-1][0]-1
                    yield init
                if generation is not None:
                    for number, fragment in fragments:
                        if number > seq:
                            seq = number
                            yield fragment
                await asyncio.sleep(.06)
        return StreamingResponse(frames(), media_type='video/mp4')

    def recording_path(name, m):
        import re
        if not re.fullmatch(r'\d{8}T\d{6}-[a-f0-9]{6}-\d{6}\.mkv', name):
            raise HTTPException(404, '录像不存在')
        p = m.recording_path(name)
        if not p.is_file() or p.is_symlink():
            raise HTTPException(404, '录像不存在或已被容量轮转清理')
        if name == m.active_name():
            raise HTTPException(409, '当前片段正在录制，请等待关闭')
        return p

    @app.get('/api/recordings/{name}')
    def download(request: Request, name: str):
        m = request.state.camera
        return PinnedFileResponse(recording_path(name,m), m, filename=name, media_type='video/x-matroska')

    @app.post('/api/playback/{name}/prepare')
    def prepare(request: Request, name: str):
        m = request.state.camera
        p = recording_path(name,m)
        try:
            return m.prepare_playback(p)
        except ValueError as exc:
            raise HTTPException(429,str(exc))

    @app.get('/api/playback/{name}/status')
    def playback_status(request: Request, name: str):
        m = request.state.camera
        path = recording_path(name,m)
        target = m.play_dir/(Path(name).stem+'.mp4')
        if target.exists():
            return {**m.playback_info(path),'state':'ready','progress':100,'url':m.scoped_url('/api/play/'+name),
                    'stream_url':m.scoped_url('/api/play/'+name+'/stream')}
        return {**m.playback_info(path),**m.playback_jobs.get(name,{'state':'not-prepared','progress':0})}

    @app.get('/api/play/{name}/stream')
    async def playback_stream(request: Request, name: str, start: float = 0):
        m = request.state.camera
        import math
        path = recording_path(name,m)
        if not math.isfinite(start) or start<0:
            raise HTTPException(400,'无效回放时间')
        target = m.play_dir/(path.stem+'.mp4')
        if not m.play_stream_slots.acquire(blocking=False):
            raise HTTPException(429,'正在切换回放，请稍后重试')
        if m.hub:
            with m.hub.storage_lock:
                m.hub.pin(path)
                m.hub.pin(target)
        try:
            job = await asyncio.to_thread(m.prepare_playback,path)
            duration = job['duration']
            if start >= duration:
                raise HTTPException(400,'回放时间超出录像长度')
        except BaseException:
            m.play_stream_slots.release()
            if m.hub:
                m.hub.unpin(path)
                m.hub.unpin(target)
            raise
        temporary = target.with_name(target.stem+'.part.mp4')
        tail_cache = start<.001 and job['state']=='processing' and not target.exists()
        async def data():
            process = None
            file = None
            next_auth_check = 0
            def authorized():
                nonlocal next_auth_check
                if time.monotonic() < next_auth_check:
                    return True
                try:
                    valid = m.auth.session(request.cookies.get('cam_session',''))
                except AuthError:
                    return False
                if not valid:
                    return False
                next_auth_check = time.monotonic()+2
                return True
            try:
                if tail_cache:
                    until = time.monotonic()+15
                    while not m.stop.is_set() and time.monotonic()<until and authorized():
                        selected = temporary if temporary.exists() else target
                        if selected.exists():
                            file=selected.open('rb');break
                        if m.playback_jobs.get(name,{}).get('state')=='error':
                            return
                        await asyncio.sleep(.04)
                    if file is None:
                        return
                    while not m.stop.is_set() and authorized():
                        chunk = await asyncio.to_thread(file.read,65536)
                        if chunk:
                            yield chunk
                        elif m.playback_jobs.get(name,{}).get('state') in ('ready','error'):
                            break
                        else:
                            await asyncio.sleep(.04)
                else:
                    cached = target.exists()
                    source = target if cached else path
                    args = ['ffmpeg','-nostdin','-hide_banner','-loglevel','error','-ss',str(start),'-i',str(source),
                            '-map','0:v:0','-map','0:a:0?']
                    if cached and start<.001:
                        args += ['-c','copy']
                    else:
                        args += ['-vf','fps=15,scale=1280:-2','-c:v','libx264','-preset','ultrafast',
                            '-tune','zerolatency','-profile:v','baseline','-level:v','3.1',
                            '-crf','23','-maxrate','2M','-bufsize','4M','-pix_fmt','yuv420p','-threads','2',
                            '-g','30','-keyint_min','30','-sc_threshold','0',
                            '-c:a','aac','-b:a','64k','-ar','48000','-ac','1',
                            '-af','aresample=async=1:first_pts=0']
                    args += ['-avoid_negative_ts','make_zero','-f','mp4',
                             '-movflags','+empty_moov+default_base_moof+frag_keyframe','-flush_packets','1','pipe:1']
                    process = await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,
                        stdin=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
                    while chunk := await process.stdout.read(65536):
                        if not authorized():
                            break
                        yield chunk
            finally:
                if file:
                    file.close()
                if process and process.returncode is None:
                    try:
                        process.terminate()
                        await asyncio.wait_for(process.wait(),2)
                    except (ProcessLookupError,asyncio.TimeoutError,asyncio.CancelledError):
                        if process.returncode is None:
                            try:process.kill()
                            except ProcessLookupError:pass
                m.play_stream_slots.release()
                if m.hub:
                    m.hub.unpin(path)
                    m.hub.unpin(target)
        return StreamingResponse(data(),media_type='video/mp4',
            headers={'X-Playback-Start':str(start),'X-Playback-Duration':str(duration),'X-Playback-Mode':'stream-while-cache'})

    @app.get('/api/play/{name}')
    def play(request: Request, name: str):
        m = request.state.camera
        recording_path(name,m)
        target = m.play_dir/(Path(name).stem+'.mp4')
        if not target.exists():
            raise HTTPException(409,'回放尚未准备完成，请从录像列表点击播放')
        # Keep Last-Modified/ETag stable across Range/If-Range seek requests.
        m.cache_access[name] = time.time()
        return PinnedFileResponse(target, m, media_type='video/mp4', headers={'Content-Disposition':'inline'})

    return app


def self_test():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        for i in range(5):
            f = p / (str(i)+'.mkv')
            f.write_bytes(b'x'*100)
            os.utime(f, (100+i, 100+i))
        total, removed = prune(p, '4.mkv', 250)
        assert total == 200 and removed == ['0.mkv', '1.mkv', '2.mkv']
        assert (p/'4.mkv').exists()
        try:
            lan_ip('8.8.8.8')
            raise AssertionError('public target allowed')
        except ValueError:
            pass
        assert lan_ip('192.168.1.10') == '192.168.1.10'
    print(json.dumps({'complete': True, 'retention_oldest_first_active_preserved': True, 'lan_target_validation': True}))


def totp_cli(argv):
    auth = AuthManager(DATA)
    if '--totp-init' in argv:
        token, expires = auth.initialize_token()
        print(json.dumps({'state': 'pending', 'token': token, 'expires_at': expires}))
        return
    if '--totp-recover' in argv:
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            raise SystemExit('TOTP恢复必须由服务器本地管理员执行')
        token, expires = auth.recover()
        print(json.dumps({'state': 'pending', 'token': token, 'expires_at': expires}))
        return
    if '--totp-status' in argv:
        print(json.dumps(auth.public_status(), ensure_ascii=False))
        return
    if '--totp-backup' in argv:
        index = argv.index('--totp-backup')
        path = Path(argv[index + 1]) if index + 1 < len(argv) else None
        if path is None:
            raise SystemExit('--totp-backup 需要目标文件路径')
        auth.backup(path, sys.stdin.readline().rstrip('\r\n'))
        print(json.dumps({'complete': True, 'path': str(path)}))
        return
    if '--totp-restore' in argv:
        index = argv.index('--totp-restore')
        path = Path(argv[index + 1]) if index + 1 < len(argv) else None
        if path is None:
            raise SystemExit('--totp-restore 需要备份文件路径')
        auth.restore(path, sys.stdin.readline().rstrip('\r\n'), force='--force' in argv)
        print(json.dumps({'complete': True, 'state': auth.state()}))
        return
    raise SystemExit('未知TOTP命令')


if __name__ == '__main__':
    os.umask(0o077)
    if '--init' in sys.argv:
        init_config()
    elif any(x in sys.argv for x in ('--totp-init', '--totp-recover', '--totp-status',
                                     '--totp-backup', '--totp-restore')):
        try:
            totp_cli(sys.argv)
        except AuthError as exc:
            raise SystemExit(exc.detail) from exc
    elif '--self-test' in sys.argv:
        self_test()
    else:
        import uvicorn
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        auth = AuthManager(DATA,session_ttl=int(os.environ.get('CAM_SESSION_TTL',str(48*3600))),
                           absolute_ttl=int(os.environ.get('CAM_SESSION_ABSOLUTE_TTL',str(30*86400))) or None)
        hub = CameraHub(DATA,CONFIG,Manager,auth,atomic_json)
        uvicorn.run(build_app(hub), host=os.environ.get('CAM_BIND_HOST',FALLBACK),
                    port=int(os.environ.get('CAM_PORT', '80')), proxy_headers=True,
                    forwarded_allow_ips=os.environ.get('CAM_TRUSTED_PROXIES','127.0.0.1,::1'),
                    access_log=False, server_header=False, workers=1, limit_concurrency=40,
                    timeout_graceful_shutdown=3)
