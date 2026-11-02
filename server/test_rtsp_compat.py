import socket
import threading
import struct

from rtsp_compat import RTSPCompat
from unittest.mock import Mock

import pytest

import rtsp_compat
from rtsp_compat import RTSPCompat, forward, rewrite_header


def test_old_camera_advertises_options_without_broken_get_parameter():
    source = b'RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, PLAY, GET_PARAMETER, SET_PARAMETER\r\n\r\n'
    result = rewrite_header(source)
    assert b'GET_PARAMETER' not in result
    assert b'Public: OPTIONS, PLAY, SET_PARAMETER' in result
    assert b'CSeq: 1' in result


def test_adapter_changes_only_control_headers_and_preserves_split_rtp_and_sdp():
    source, writer = socket.socketpair()
    destination, reader = socket.socketpair()
    reader.settimeout(2)
    body = b'v=0\r\ni=Public: GET_PARAMETER\r\na=control:track1\r\n'
    message = b'RTSP/1.0 200 OK\r\nPublic: OPTIONS, GET_PARAMETER\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    payload = b'\x24\x00\x00\x08'+b'\x24PUBLIC!'
    expected = rewrite_header(message[:message.index(b'\r\n\r\n')+4])+body+payload
    thread = threading.Thread(target=forward,args=(source,destination),daemon=True)
    thread.start()
    for index in range(0,len(message+payload),3):
        writer.sendall((message+payload)[index:index+3])
    writer.shutdown(socket.SHUT_WR)
    output = bytearray()
    while len(output)<len(expected):
        output.extend(reader.recv(4096))
    assert bytes(output)==expected
    thread.join(2)
    assert not thread.is_alive()
    for s in (source,writer,destination,reader):s.close()


def test_loopback_request_authority_rewritten_but_media_body_not_reencoded():
    header = b'DESCRIBE rtsp://127.0.0.1:1234/stream1 RTSP/1.0\r\nCSeq: 2\r\n\r\n'
    result = rewrite_header(header,'rtsp://192.168.1.11:554','rtsp://127.0.0.1:1234')
    assert result.startswith(b'DESCRIBE rtsp://192.168.1.11:554/stream1 RTSP/1.0')


def test_bridge_sends_compound_rtcp_receiver_report(monkeypatch):
    upstream=socket.socket();upstream.bind(('127.0.0.1',0));upstream.listen(1)
    upstream.settimeout(8)
    connect=socket.create_connection
    monkeypatch.setattr(socket,'create_connection',lambda address,**kwargs:
                        connect(upstream.getsockname() if address[1]==554 else address,**kwargs))
    stop=threading.Event();adapter=RTSPCompat(lambda:'127.0.0.1',stop)
    adapter.url()
    client=connect(('127.0.0.1',adapter.port),timeout=8)
    client.sendall(b'OPTIONS rtsp://127.0.0.1:'+str(adapter.port).encode()+b'/stream1 RTSP/1.0\r\nCSeq: 1\r\n\r\n')
    server,_=upstream.accept();server.settimeout(8)
    server.recv(4096)
    rtp=struct.pack('!BBHII',0x80,96,1234,5678,0x11223344)+b'payload'
    frame=b'$\x00'+len(rtp).to_bytes(2,'big')+rtp
    server.sendall(frame)
    assert client.recv(4096)==frame
    report=bytearray()
    while len(report)<4:report.extend(server.recv(4096))
    length=int.from_bytes(report[2:4],'big')
    while len(report)<length+4:report.extend(server.recv(4096))
    assert report[:2]==b'$\x01'
    assert report[4:8]==b'\x81\xc9\x00\x07'
    assert report[12:16]==struct.pack('!I',0x11223344)
    assert report[20:24]==struct.pack('!I',1234)
    assert report[36:38]==b'\x81\xca'
    stop.set()
    for s in (client,server,upstream):s.close()


def forwarded_chunks(chunks, **kwargs):
    """Exercise framing without creating a listener or opening any connection."""
    source = Mock()
    source.recv.side_effect = [*chunks, b'']
    destination = Mock()
    forward(source, destination, **kwargs)
    return b''.join(bytes(call.args[0]) for call in destination.sendall.call_args_list)


@pytest.mark.parametrize('chunk_size', [1, 3, 65536])
def test_multiple_messages_binary_channels_and_body_are_byte_exact(chunk_size):
    body = b'v=0\r\ni=Public: GET_PARAMETER\r\n\x24\x00\x00\x04\r\n\r\n'
    header = (b'RTSP/1.0 200 OK\r\nCSeq: 5\r\npUbLiC: OPTIONS, get_parameter, PLAY\r\n'
              b'content-length: ' + str(len(body)).encode() + b'\r\n\r\n')
    # Both RTP and RTCP framing, zero-length frame, and maximum 16-bit payload.
    frames = (b'\x24\x00\x00\x00' + b'\x24\x01\x00\x08' + b'PUBLIC!$' +
              b'\x24\x02\xff\xff' + bytes(range(256)) * 255 + bytes(range(255)))
    final = b'RTSP/1.0 200 OK\r\nCSeq: 6\r\nSession: fixture;timeout=65\r\n\r\n'
    wire = header + body + frames + final
    chunks = [wire[i:i + chunk_size] for i in range(0, len(wire), chunk_size)]
    assert forwarded_chunks(chunks) == rewrite_header(header) + body + frames + final


def test_request_rewrite_does_not_touch_sdp_or_interleaved_payload():
    local = 'rtsp://127.0.0.1:1234'
    target = 'rtsp://192.168.1.11:554'
    body = (local + '/stream1\r\nPublic: GET_PARAMETER\r\n').encode()
    header = (b'SET_PARAMETER ' + local.encode() + b'/stream1 RTSP/1.0\r\n'
              b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n')
    frame = b'\x24\x01' + len(body).to_bytes(2, 'big') + body
    assert forwarded_chunks([header + body + frame], target=target, loopback=local) == (
        rewrite_header(header, target, local) + body + frame)


@pytest.mark.parametrize('wire', [b'X' * (2 * 1024 * 1024 + 1),
    b'RTSP/1.0 200 OK\r\nContent-Length: 2097152\r\n\r\n'], ids=['oversized-header', 'oversized-body'])
def test_oversized_headers_or_declared_body_fail_without_forwarding(wire):
    source, destination = Mock(), Mock()
    source.recv.side_effect = [wire, b'']
    with pytest.raises(ValueError):
        forward(source, destination)
    destination.sendall.assert_not_called()


@pytest.mark.parametrize('has_ip', [False, True])
def test_bridge_releases_connection_slot_on_unavailable_camera(monkeypatch, has_ip):
    adapter = RTSPCompat.__new__(RTSPCompat)
    adapter.get_ip = lambda: '192.168.1.11' if has_ip else None
    adapter.slots = threading.BoundedSemaphore(1)
    assert adapter.slots.acquire(blocking=False)
    client = Mock()
    connect = Mock(side_effect=OSError('offline fixture'))
    monkeypatch.setattr(rtsp_compat.socket, 'create_connection', connect)
    adapter.bridge(client)
    client.close.assert_called_once()
    assert adapter.slots.acquire(blocking=False)
    assert not adapter.slots.acquire(blocking=False)
    adapter.slots.release()
    assert connect.call_count == int(has_ip)
