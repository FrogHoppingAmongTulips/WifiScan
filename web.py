#!/usr/bin/env python3
"""Веб-вид тех же данных, что и в терминале. Только stdlib.

Слушает только петлю: сеть, за которой смотрит wfs, — не та сеть, в которую
его стоит выставлять. Страница отдаётся целиком одним файлом, данные приходят
отдельными запросами, чтобы открытая вкладка обновлялась без перезагрузки.
"""
import json
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import connections
import wifi_cli

PAGE = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wfs</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#000;color:#fff;
  font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
  -webkit-font-smoothing:antialiased}
main{max-width:820px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:14px;font-weight:400;letter-spacing:.18em;text-transform:uppercase;
  color:#666;margin:0 0 22px}
nav{display:flex;gap:20px;margin:0 0 26px}
nav button{background:none;border:0;padding:0;font:inherit;color:#666;cursor:pointer}
nav button.on{color:#fff}
nav button:hover{color:#fff}
.row{border:0;background:none;width:100%;padding:9px 0;font:inherit;color:#fff;
  text-align:left;cursor:pointer;display:flex;gap:14px;align-items:baseline;
  border-bottom:1px solid #161616}
.row:hover{color:#fff}
.row .k{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .v{color:#666;white-space:nowrap}
.row.on .v{color:#fff}
.det{display:none;padding:4px 0 16px 0;border-bottom:1px solid #161616}
.det.on{display:block}
.det div{display:flex;gap:14px;padding:3px 0}
.det .n{color:#666;width:150px;flex-shrink:0}
.empty,.note{color:#666;padding:10px 0}
@media(max-width:560px){.det .n{width:110px}main{padding:20px 14px 50px}}
</style>
<main>
  <h1>wfs</h1>
  <nav>
    <button data-tab="devices" class="on">устройства</button>
    <button data-tab="out">исходящие</button>
  </nav>
  <div id="body" class="note">читаю…</div>
</main>
<script>
let tab = 'devices', open = null, data = {devices: null, out: null};

function esc(s){return String(s == null ? '' : s).replace(/[<>&"]/g,
  c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]))}

function rows(list, key, val, detail){
  if(!list || !list.length) return '<div class="empty">пусто</div>';
  return list.map((it, i) => {
    const id = tab + i;
    const body = Object.entries(detail(it))
      .filter(([, v]) => v !== '' && v != null)
      .map(([n, v]) => '<div><span class="n">' + esc(n) + '</span><span>' + esc(v) + '</span></div>')
      .join('');
    return '<button class="row' + (open === id ? ' on' : '') + '" data-id="' + id + '">' +
             '<span class="k">' + esc(key(it)) + '</span>' +
             '<span class="v">' + esc(val(it)) + '</span>' +
           '</button>' +
           '<div class="det' + (open === id ? ' on' : '') + '" data-for="' + id + '">' + body + '</div>';
  }).join('');
}

function render(){
  const b = document.getElementById('body');
  const d = data[tab];
  if(d === null){ b.className = 'note'; b.textContent = 'читаю…'; return }
  b.className = '';
  if(tab === 'devices'){
    b.innerHTML = rows(d, x => x.name || x.hostname || x.ip, x => x.ip, x => ({
      'адрес': x.ip, 'mac': x.mac, 'имя': x.name || x.hostname,
      'производитель': x.vendor, 'тип': x.type, 'система': x.os_hint,
      'порты': (x.ports || []).join(' '),
      'это шлюз': x.is_gateway ? 'да' : '', 'это я': x.is_me ? 'да' : '',
      'случайный mac': x.random_mac ? 'да' : '',
      'впервые замечен': x.first_seen, 'последний раз': x.last_seen,
    }));
  } else {
    b.innerHTML = rows(d, x => x.app, x => x.country || x.ip, x => ({
      'программа': x.app, 'адрес': x.ip, 'порт': x.port,
      'имя сервера': x.rdns, 'страна': x.country, 'владелец': x.org,
    }));
  }
}

async function load(which){
  try{
    const r = await fetch('/api/' + which);
    data[which] = await r.json();
  }catch(e){ data[which] = [] }
  if(which === tab) render();
}

document.addEventListener('click', e => {
  const t = e.target.closest('nav button');
  if(t){
    tab = t.dataset.tab; open = null;
    document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b === t));
    render();
    if(data[tab] === null) load(tab);
    return;
  }
  const row = e.target.closest('.row');
  if(!row) return;
  const id = row.dataset.id;
  open = (open === id) ? null : id;
  render();
});

load('devices');
setInterval(() => { data[tab] = null; load(tab) }, 30000);
</script>
"""


def _devices():
    devices = wifi_cli.full_scan(quiet=True)
    return devices


def _outgoing():
    conns = connections.list_connections()
    ips = list({c['ip'] for c in conns})
    # Из кэша: страница не должна ходить наружу без спроса.
    geo = connections.geo_lookup(ips, allow_network=False)
    rdns = connections.reverse_dns_batch(ips)
    out = []
    for c in conns:
        g = geo.get(c['ip'], {})
        out.append({
            'app': c.get('app', ''), 'ip': c['ip'], 'port': c.get('port', ''),
            'rdns': rdns.get(c['ip'], ''),
            'country': g.get('country', ''), 'org': g.get('org', ''),
        })
    out.sort(key=lambda x: (x['app'].lower(), x['ip']))
    return out


class Handler(BaseHTTPRequestHandler):
    # Тихо: обычный лог http.server пишет строку на каждый запрос и мешает
    # читать то, ради чего терминал открыт.
    def log_message(self, *a):
        pass

    def _send(self, body, ctype):
        raw = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == '/':
            return self._send(PAGE, 'text/html; charset=utf-8')
        if self.path == '/api/devices':
            return self._send(json.dumps(_devices(), ensure_ascii=False), 'application/json')
        if self.path == '/api/out':
            return self._send(json.dumps(_outgoing(), ensure_ascii=False), 'application/json')
        self.send_error(404)


def free_port(preferred=8787):
    """Занятый порт — не повод падать: берётся любой свободный."""
    for port in (preferred, 0):
        try:
            s = socket.socket()
            s.bind(('127.0.0.1', port))
            port = s.getsockname()[1]
            s.close()
            return port
        except OSError:
            continue
    return 0


def serve(port=None, open_browser=True):
    port = port or free_port()
    srv = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    url = f'http://127.0.0.1:{port}'
    print(url)
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == '__main__':
    import sys
    # --no-open — для случая, когда команду запускают не с того компьютера,
    # за которым сидят: по ссылке всё равно можно зайти вручную.
    serve(open_browser='--no-open' not in sys.argv)
