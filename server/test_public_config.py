"""Public configuration import and deployment network boundaries; offline only."""
import io
import ipaddress
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import camera_web


def test_full_example_config_import_is_non_overwriting(tmp_path, monkeypatch):
    config = json.loads(Path(__file__).with_name('config.example.json').read_text(encoding='utf-8'))
    monkeypatch.setattr(camera_web, 'DATA', tmp_path)
    monkeypatch.setattr(camera_web, 'CONFIG', tmp_path / 'config.json')
    monkeypatch.setattr(camera_web.sys, 'stdin', io.StringIO(json.dumps(config)))
    camera_web.init_config()
    assert json.loads(camera_web.CONFIG.read_text(encoding='utf-8')) == config
    with pytest.raises(SystemExit, match='already exists'):
        camera_web.init_config()


@pytest.mark.parametrize('mutation', ['missing_device', 'empty_identity', 'outside_network', 'missing_key'])
def test_invalid_new_deployment_does_not_write_config(tmp_path, monkeypatch, mutation):
    config = json.loads(Path(__file__).with_name('config.example.json').read_text(encoding='utf-8'))
    if mutation == 'missing_device':
        del config['cameras']['cam2']
    elif mutation == 'empty_identity':
        config['cameras']['cam2']['expected_mac'] = ''
    elif mutation == 'outside_network':
        config['cameras']['cam2']['manual_ip'] = '8.8.8.8'
    else:
        del config['cameras']['cam1']['camera_host_key']
    monkeypatch.setattr(camera_web, 'DATA', tmp_path)
    monkeypatch.setattr(camera_web, 'CONFIG', tmp_path / 'config.json')
    monkeypatch.setattr(camera_web.sys, 'stdin', io.StringIO(json.dumps(config)))
    with pytest.raises((SystemExit, ValueError)):
        camera_web.init_config()
    assert not camera_web.CONFIG.exists()


def test_configured_subnet_boundaries_and_server_are_rejected(monkeypatch):
    monkeypatch.setattr(camera_web, 'NETWORK', ipaddress.IPv4Network('10.23.4.0/23'))
    monkeypatch.setattr(camera_web, 'FALLBACK', '10.23.4.2')
    assert camera_web.lan_ip('10.23.4.255') == '10.23.4.255'
    assert camera_web.lan_ip('10.23.5.0') == '10.23.5.0'
    for value in ['10.23.4.0', '10.23.5.255', '10.23.4.2', '192.168.1.10']:
        with pytest.raises(ValueError):
            camera_web.lan_ip(value)
