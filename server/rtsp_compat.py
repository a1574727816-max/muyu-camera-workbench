"""Loopback TCP adapter for older TP-Link RTSP/RTCP keepalive compatibility.

Forwards original media/SDP unchanged and adds bounded compound receiver reports.
"""
import re
import secrets
import socket
import struct
import threading


def rewrite_header(header, target=None, loopback=None):
    if target:
        header = header.replace(loopback.encode(), target.encode())
    lines = header.split(b'\r\n')
    for index, line in enumerate(lines):
        if line.lower().startswith(b'public:'):
            methods = [m.strip() for m in line.split(b':',1)[1].split(b',')]
            lines[index] = b'Public: ' + b', '.join(m for m in methods if m.upper() != b'GET_PARAMETER')
    return b'\r\n'.join(lines)


def forward(source, destination, *, target=None, loopback=None, on_frame=None, send_lock=None):
    def send(data):
        if send_lock:
            with send_lock:destination.sendall(data)
        else:destination.sendall(data)
    buf = bytearray()
    while True:
        block = source.recv(65536)
        if not block:
            return
        buf.extend(block)
        if len(buf) > 2*1024*1024:
            raise ValueError('RTSP adapter message too large')
        while buf:
            if buf[0] == 36:
                if len(buf) < 4:
                    break
                length = 4 + int.from_bytes(buf[2:4],'big')
                if len(buf) < length:
                    break
                send(buf[:length])
                if on_frame:
                    on_frame(buf[1],bytes(buf[4:length]))
                del buf[:length]
                continue
            end = buf.find(b'\r\n\r\n')
            if end < 0:
                break
            end += 4
            header = bytes(buf[:end])
            match = re.search(rb'(?im)^Content-Length:\s*(\d+)',header)
            length = end + (int(match[1]) if match else 0)
            if length > 2*1024*1024:
                raise ValueError('RTSP adapter body too large')
            if len(buf) < length:
                break
            send(rewrite_header(header,target,loopback) + bytes(buf[end:length]))
            del buf[:length]


class RTSPCompat:
    def __init__(self, get_ip, stop):
        self.get_ip, self.stop = get_ip, stop
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1',0))
        self.listener.listen(4)
        self.listener.settimeout(1)
        self.port = self.listener.getsockname()[1]
        self.slots = threading.BoundedSemaphore(4)
        self.started = False

    def url(self):
        if not self.started:
            self.started = True
            threading.Thread(target=self.run,daemon=True).start()
        return 'rtsp://127.0.0.1:'+str(self.port)+'/stream1'

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    client,_ = self.listener.accept()
                except socket.timeout:
                    continue
                if not self.slots.acquire(blocking=False):
                    client.close()
                    continue
                threading.Thread(target=self.bridge,args=(client,),daemon=True).start()
        finally:
            self.listener.close()

    def bridge(self, client):
        upstream = None
        done = threading.Event()
        try:
            ip = self.get_ip()
            if not ip:
                return
            upstream = socket.create_connection((ip,554),timeout=6)
            upstream.settimeout(80)
            client.settimeout(80)
            send_lock, stats_lock = threading.Lock(), threading.Lock()
            streams = {}
            receiver_ssrc = secrets.randbits(32)
            def observe(channel, packet):
                if channel%2 or len(packet)<12 or packet[0]>>6!=2:
                    return
                seq=int.from_bytes(packet[2:4],'big');ssrc=int.from_bytes(packet[8:12],'big')
                with stats_lock:
                    item=streams.get(channel)
                    if item is None or item['ssrc']!=ssrc:
                        item=dict(ssrc=ssrc,base=seq,highest=seq,received=0,seen=set(),expected_prior=0,received_prior=0)
                        streams[channel]=item
                    highest=item['highest'];extended=(highest&~65535)|seq
                    if extended<highest-32768:extended+=65536
                    elif extended>highest+32768:extended-=65536
                    if extended not in item['seen']:
                        item['received']+=1;item['seen'].add(extended)
                    item['highest']=max(highest,extended)
                    if len(item['seen'])>256:
                        item['seen']={n for n in item['seen'] if n>=item['highest']-128}
            def reports():
                while not done.wait(5) and not self.stop.is_set():
                    with stats_lock:
                        frames=[]
                        for channel,item in streams.items():
                            expected=item['highest']-item['base']+1
                            loss=max(-8388608,min(8388607,expected-item['received']))
                            interval=expected-item['expected_prior'];received=item['received']-item['received_prior']
                            fraction=max(0,min(255,((interval-received)<<8)//interval)) if interval>0 else 0
                            item['expected_prior'],item['received_prior']=expected,item['received']
                            # Jitter/SR timing omitted (zero) rather than fabricated.
                            rr=struct.pack('!BBHII',0x81,201,7,receiver_ssrc,item['ssrc'])
                            rr+=bytes([fraction])+(loss&0xffffff).to_bytes(3,'big')
                            rr+=struct.pack('!IIII',item['highest']&0xffffffff,0,0,0)
                            cname=b'cam-manager'
                            body=struct.pack('!I',receiver_ssrc)+bytes([1,len(cname)])+cname+b'\0'
                            body+=b'\0'*((-len(body))%4)
                            compound=rr+struct.pack('!BBH',0x81,202,len(body)//4)+body
                            frames.append(b'$'+bytes([channel+1])+struct.pack('!H',len(compound))+compound)
                    try:
                        with send_lock:
                            for frame in frames:upstream.sendall(frame)
                    except OSError:return
            def responses():
                try:
                    forward(upstream,client,on_frame=observe)
                except (OSError,ValueError):
                    pass
                finally:
                    try:client.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
            threading.Thread(target=responses,daemon=True).start()
            threading.Thread(target=reports,daemon=True).start()
            forward(client,upstream,target='rtsp://'+ip+':554',
                    loopback='rtsp://127.0.0.1:'+str(self.port),send_lock=send_lock)
        except (OSError,ValueError):
            pass
        finally:
            done.set()
            for endpoint in (client,upstream):
                if endpoint:
                    try:endpoint.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                    endpoint.close()
            self.slots.release()
