#!/usr/bin/env python3
"""Тесты на объединённую часть: исходящие соединения и веб-вид.

Сеть не трогается: geo подставляется через кэш, соединения — через подмену
чтения системы. Запуск: `python3 tests/test_merged.py`.
"""
import json
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import connections
import netmon
import web


# ── исходящие соединения ──────────────────────────────────────────────────────

def test_geo_does_not_touch_network_by_default():
    """Инструмент, который показывает, куда уходят данные, не должен сам
    отправлять их список наружу без спроса."""
    called = []

    def boom(*a, **kw):
        called.append(a)
        raise AssertionError('запрос наружу без разрешения')

    orig = connections.urllib.request.urlopen
    connections.urllib.request.urlopen = boom
    try:
        got = connections.geo_lookup(['8.8.8.8'], allow_network=False)
    finally:
        connections.urllib.request.urlopen = orig

    assert called == [], 'был запрос наружу'
    assert got['8.8.8.8']['country'] == '?', got


def test_unknown_geo_is_not_a_warning():
    """Без запроса наружу страна и владелец неизвестны у всех. Если считать
    это подозрительным, помеченным окажется каждое соединение, и метки
    перестанут что-либо значить."""
    conn = {'ip': '1.2.3.4', 'port': '443', 'app': 'Safari'}
    quiet = netmon.flag_connection(conn, {}, geo_known=False)
    assert quiet == [], quiet

    loud = netmon.flag_connection(conn, {}, geo_known=True)
    assert 'unknown location' in loud, loud


def test_unusual_port_is_flagged_either_way():
    """Порт не зависит от справочника: он виден всегда и метку терять нельзя."""
    conn = {'ip': '1.2.3.4', 'port': '4444', 'app': 'что-то'}
    for known in (True, False):
        flags = netmon.flag_connection(conn, {}, geo_known=known)
        assert any('4444' in f for f in flags), (known, flags)


def test_no_third_party_library_needed():
    """Оба проекта собирались как «ноль зависимостей». Слияние это не отменяет."""
    for mod in (connections, netmon, web):
        src = Path(mod.__file__).read_text()
        assert 'import requests' not in src, mod.__file__


# ── веб-вид ───────────────────────────────────────────────────────────────────

def _serve():
    """Поднимает сервер на свободном порту и возвращает адрес и как погасить."""
    port = web.free_port()
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(('127.0.0.1', port), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f'http://127.0.0.1:{port}', srv.shutdown


def test_page_is_black_and_self_contained():
    """Страница должна открываться без сети: ни одного стороннего адреса, и
    цвета те, о которых договаривались."""
    page = web.PAGE
    assert 'background:#000' in page and 'color:#fff' in page
    for bad in ('http://', 'https://', 'cdn', '<img'):
        assert bad not in page, f'страница тянет наружу: {bad}'


def test_outgoing_shape():
    """Веб и терминал читают одно и то же; поля не должны разъезжаться."""
    fake = [{'app': 'Safari', 'ip': '1.2.3.4', 'port': '443'}]
    orig_list = connections.list_connections
    orig_rdns = connections.reverse_dns_batch
    connections.list_connections = lambda: fake
    connections.reverse_dns_batch = lambda ips: {'1.2.3.4': 'example.net'}
    try:
        rows = web._outgoing()
    finally:
        connections.list_connections = orig_list
        connections.reverse_dns_batch = orig_rdns

    assert len(rows) == 1
    row = rows[0]
    for field in ('app', 'ip', 'port', 'rdns', 'country', 'org'):
        assert field in row, field
    assert row['rdns'] == 'example.net'


def test_server_answers_and_refuses_unknown_paths():
    url, stop = _serve()
    try:
        with urllib.request.urlopen(url + '/', timeout=10) as r:
            body = r.read().decode()
        assert r.status == 200 and '<title>wfs</title>' in body

        fake = [{'app': 'Safari', 'ip': '1.2.3.4', 'port': '443'}]
        orig = connections.list_connections
        connections.list_connections = lambda: fake
        try:
            with urllib.request.urlopen(url + '/api/out', timeout=15) as r:
                data = json.loads(r.read().decode())
        finally:
            connections.list_connections = orig
        assert isinstance(data, list) and data[0]['app'] == 'Safari'

        try:
            urllib.request.urlopen(url + '/../etc/passwd', timeout=5)
            raise AssertionError('отдал то, чего не должно быть')
        except urllib.error.HTTPError as e:
            assert e.code == 404, e.code
    finally:
        stop()


def test_server_listens_on_loopback_only():
    """Сеть, за которой смотрит wfs, — не та сеть, в которую его стоит
    выставлять."""
    src = Path(web.__file__).read_text()
    assert "'0.0.0.0'" not in src and '"0.0.0.0"' not in src
    assert "ThreadingHTTPServer(('127.0.0.1'" in src


def test_free_port_returns_something_bindable():
    import socket
    port = web.free_port()
    assert 0 < port < 65536
    s = socket.socket()
    try:
        s.bind(('127.0.0.1', port))
    finally:
        s.close()


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
