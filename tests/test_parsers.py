#!/usr/bin/env python3
"""Pure unit tests (no network). Run with `pytest` or `python3 tests/test_parsers.py`."""
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import identify
import security
import exporter
import store as store_mod
import config as config_mod
import wifi_cli


# ── identify: DNS name decoding ───────────────────────────────────────────────

def test_decode_name():
    data = b'\x03abc\x05local\x00'
    name, off = identify.decode_name(data, 0)
    assert name == 'abc.local'
    assert off == len(data)


def test_parse_response_a_record():
    header = struct.pack('>HHHHHH', 0, 0x8400, 0, 1, 0, 0)
    rr = b'\x04host\x05local\x00' + struct.pack('>HHIH', 1, 1, 120, 4) + bytes([192, 168, 1, 50])
    res = identify.parse_response(header + rr)
    assert ('host.local', 'A', '192.168.1.50') in res


def test_parse_response_txt_model():
    header = struct.pack('>HHHHHH', 0, 0x8400, 0, 1, 0, 0)
    txt = b'\x09model=X12'
    rr = b'\x01x\x05local\x00' + struct.pack('>HHIH', 16, 1, 120, len(txt)) + txt
    res = identify.parse_response(header + rr)
    txt_recs = [r for r in res if r[1] == 'TXT']
    assert txt_recs and txt_recs[0][2].get('model') == 'X12'


# ── wifi_cli: pure classifiers ────────────────────────────────────────────────

def test_is_random_mac():
    assert wifi_cli.is_random_mac('AE:E6:91:ED:5B:73') is True   # 2nd bit of 1st byte set
    assert wifi_cli.is_random_mac('38:6B:1C:57:98:45') is False
    assert wifi_cli.is_random_mac('') is False


def test_get_device_type():
    assert wifi_cli.get_device_type('Apple', 'MacBook') == 'Apple Device'
    assert wifi_cli.get_device_type('', 'somebody-iphone') == 'Apple Device'
    assert wifi_cli.get_device_type('', 'unknown-thing') == 'Unknown'


def test_lookup_vendor_builtin():
    assert wifi_cli.lookup_vendor('38:6B:1C:AA:BB:CC') == 'Arcadyan'
    assert wifi_cli.lookup_vendor('AE:E6:91:00:00:00') == 'Private/Randomized'


def test_parse_arp_output():
    text = ("? (192.168.1.1) at 38:6b:1c:57:98:45 on en0 ifscope [ethernet]\n"
            "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 [ethernet]\n"
            "host.local (192.168.1.50) at aa:bb:cc:dd:ee:ff on en0 [ethernet]")
    out = wifi_cli.parse_arp_output(text)
    assert out['192.168.1.1']['mac'] == '38:6B:1C:57:98:45'
    assert '192.168.1.255' not in out                 # broadcast dropped
    assert out['192.168.1.50']['hostname'] == 'host.local'
    assert out['192.168.1.1']['hostname'] == ''        # '?' → empty


def test_parse_nmap_output():
    text = ("Nmap scan report for 192.168.1.1\nHost is up (0.002s latency).\n"
            "Nmap scan report for phone.local (192.168.1.20)\n"
            "MAC Address: AA:BB:CC:DD:EE:FF (Apple)")
    out = wifi_cli.parse_nmap_output(text)
    assert '192.168.1.1' in out
    assert out['192.168.1.20']['hostname'] == 'phone.local'
    assert out['192.168.1.20']['mac'] == 'AA:BB:CC:DD:EE:FF'
    assert out['192.168.1.20']['vendor'] == 'Apple'


# ── security: scoring + report ────────────────────────────────────────────────

def test_security_levels():
    assert security._level(0) == 'OK'
    assert security._level(10) == 'LOW'
    assert security._level(18) == 'MEDIUM'
    assert security._level(35) == 'HIGH'
    assert security._level(60) == 'CRITICAL'


def test_security_audit_empty():
    assert security.audit([]) == []


def test_security_report_json(tmp_path=None):
    d = Path(tmp_path or tempfile.mkdtemp())
    audited = [{'device': {'ip': '192.168.1.1', 'name': 'R', 'is_gateway': True},
                'score': 60, 'level': 'CRITICAL', 'open_ports': [23], 'reasons': ['Telnet open']}]
    p = security.write_report_json(audited, d)
    import json
    data = json.loads(p.read_text())
    assert data['findings'][0]['level'] == 'CRITICAL'


# ── exporter ──────────────────────────────────────────────────────────────────

def test_exporter_json_csv():
    devices = [{'ip': '192.168.1.1', 'mac': 'AA', 'name': 'R', 'type': 'Router'}]
    js = exporter.to_json(devices)
    assert '"device_count": 1' in js and '192.168.1.1' in js
    csv_out = exporter.to_csv(devices)
    assert csv_out.splitlines()[0].startswith('ip,mac,name')
    assert '192.168.1.1' in csv_out


# ── store round-trip (temp db) ────────────────────────────────────────────────

def test_store_roundtrip():
    tmp = Path(tempfile.mkdtemp()) / 'h.db'
    s = store_mod.Store(tmp)
    assert s.ok
    devs = [{'ip': '192.168.1.5', 'mac': 'AA:BB:CC:DD:EE:FF', 'name': 'X', 'type': 'Phone'}]
    assert 'AA:BB:CC:DD:EE:FF' in s.record_scan(devs)   # new first time
    assert not s.record_scan(devs)                       # not new second time
    s.annotate(devs)
    assert devs[0]['times_seen'] == 2


def test_store_gateway_mac_change():
    tmp = Path(tempfile.mkdtemp()) / 'h.db'
    s = store_mod.Store(tmp)
    assert s.check_gateway_mac('AA:BB:CC:00:00:01')[0] == 'first'
    assert s.check_gateway_mac('AA:BB:CC:00:00:01')[0] == 'ok'
    status, prev = s.check_gateway_mac('DE:AD:BE:EF:00:00')
    assert status == 'changed' and prev == 'AA:BB:CC:00:00:01'


def test_store_port_delta():
    tmp = Path(tempfile.mkdtemp()) / 'h.db'
    s = store_mod.Store(tmp)
    d = {'ip': '192.168.1.9', 'mac': 'BB:BB:BB:BB:BB:BB'}
    assert s.update_ports(d, [80]) == []          # no previous snapshot
    assert s.update_ports(d, [80, 23]) == [80]    # previous was [80]


# ── config defaults ───────────────────────────────────────────────────────────

def test_config_defaults(tmp_path=None):
    d = Path(tmp_path or tempfile.mkdtemp())
    config_mod.CONFIG_DIR = d
    config_mod.CONFIG_PATH = d / 'config.json'
    cfg = config_mod.load()
    assert cfg['interface'] == 'en0'
    assert config_mod.CONFIG_PATH.exists()   # materialised on first load


def test_recommend_channel():
    # соседи забили 36/40 → рекомендация должна уйти от них (в UNII-3)
    ch, load = wifi_cli.recommend_channel([36, 36, 40, 44])
    assert ch in (149, 153, 157, 161) and load == 0
    # пустой эфир → предпочитаем 149+
    assert wifi_cli.recommend_channel([])[0] >= 149


def test_sparkline():
    assert wifi_cli.sparkline([]) == ''
    s = wifi_cli.sparkline([1, 2, 3, 4])
    assert len(s) == 4 and s[0] < s[-1]           # растёт


def test_quality_verdict():
    assert wifi_cli._quality_verdict({'received': 0}) == 'НЕТ ОТВЕТА'
    assert wifi_cli._quality_verdict({'received': 20, 'loss': 0, 'jitter': 2, 'avg': 5}) == 'отлично'
    assert wifi_cli._quality_verdict({'received': 20, 'loss': 10, 'jitter': 2, 'avg': 5}) == 'проблемы'


def test_banner_risk():
    hits = identify.banner_risk({'http': 'Server: GoAhead-Webs'})
    assert any('GoAhead' in h for h in hits)
    assert identify.banner_risk({'http': 'nginx'}) == []


# ── plain runner (no pytest needed) ───────────────────────────────────────────

if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_') and callable(v)]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
