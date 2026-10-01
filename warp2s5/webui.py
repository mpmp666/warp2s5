"""A dependency-free web UI for the WARP pool.

Dashboard + JSON API built on nothing but ``asyncio`` and the standard library:

    GET  /                     dashboard (auto refreshing)
    GET  /api/status           pool + per instance status
    POST /api/start?name=x     start one instance        (also: stop, restart)
    POST /api/start-all        start every instance      (also: stop-all)
    POST /api/add?endpoint=..  add an instance (optionally pinned to an endpoint)
    POST /api/remove?name=x    remove an instance
    GET  /api/scan             endpoint scan state (live endpoints first)
    POST /api/scan             start a background endpoint scan
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

from .multi import WarpPool
from .scan import EndpointScanner

log = logging.getLogger("warp2s5.webui")

PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>warp2s5 控制台</title>
<style>
 :root{color-scheme:dark}
 body{font:14px/1.5 ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e8ee}
 header{padding:16px 22px;border-bottom:1px solid #232733;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
 h1{font-size:17px;margin:0;font-weight:600}
 h2{font-size:14px;margin:0 0 8px;font-weight:600;color:#c8cfdd}
 .sub{color:#8b93a7;font-size:12px}
 .wrap{padding:18px 22px}
 button{background:#1d2230;color:#dbe1ef;border:1px solid #2f3547;border-radius:7px;padding:6px 11px;cursor:pointer;font-size:13px}
 button:hover{background:#252c3d}
 button.primary{background:#2b6cff;border-color:#2b6cff;color:#fff}
 button.danger{background:#3a1f26;border-color:#5b2b35;color:#ffb3bf}
 button.tiny{padding:3px 8px;font-size:12px}
 table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1e2330}
 th{color:#8b93a7;font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
 tr:hover td{background:#141824}
 code{background:#171b26;padding:2px 6px;border-radius:5px;font-size:12px}
 .pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:600}
 .running{background:#123524;color:#5ce6a0}.stopped{background:#22262f;color:#98a1b5}
 .starting{background:#33291393;color:#ffce6b}.error{background:#3a1d24;color:#ff9db0}
 .live{background:#123524;color:#5ce6a0}.dead{background:#22262f;color:#98a1b5}
 .muted{color:#7c8497}
 .row-actions{display:flex;gap:6px;flex-wrap:wrap}
 .panel{border:1px solid #232733;border-radius:10px;padding:14px 16px;margin-top:18px;background:#12151d}
 .metrics{margin-top:10px;color:#8b93a7;font-size:12px}
 .grid{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
 .ep{border:1px solid #2b3145;border-radius:8px;padding:7px 10px;display:flex;gap:9px;align-items:center;background:#171b26}
 select,input{background:#171b26;color:#e6e8ee;border:1px solid #2f3547;border-radius:7px;padding:6px 9px;font-size:13px}
 dialog{background:#12151d;color:#e6e8ee;border:1px solid #2b3145;border-radius:12px;padding:20px;min-width:380px}
 dialog::backdrop{background:#000a}
 label{display:block;margin:12px 0 5px;color:#9aa3b8;font-size:12px}
</style></head><body>
<header>
  <h1>warp2s5 控制台</h1>
  <span class="sub" id="summary">加载中…</span>
  <span style="flex:1"></span>
  <button id="btn-scan">扫描端点</button>
  <button class="danger" id="btn-scan-stop" style="display:none">■ 停止扫描</button>
  <button class="primary" data-act="start-all">全部启动</button>
  <button data-act="stop-all">全部停止</button>
  <button class="primary" id="btn-add">新增实例</button>
</header>
<div class="wrap">
  <table>
    <thead><tr><th>实例</th><th>状态</th><th>SOCKS5</th><th>端点</th><th>设备</th>
      <th>流量</th><th>在线</th><th>操作</th></tr></thead>
    <tbody id="rows"><tr><td colspan="8" class="muted">加载中…</td></tr></tbody>
  </table>
  <div class="metrics" id="metrics"></div>

  <div class="panel">
    <h2>端点扫描 <span class="sub" id="scan-state"></span></h2>
    <div class="sub">只列出「握手 + CONNECT-IP + 隧道内 DNS 真的收到回包」的端点。点一下就用它新建实例。</div>
    <div class="grid" id="endpoints"><span class="sub">还没扫描过，点右上角「扫描端点」</span></div>
  </div>

  <p class="sub" style="margin-top:18px">
    用法：<code>curl -x socks5h://127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace</code>
  </p>
</div>

<dialog id="dlg-add">
  <h2>新增 WARP 实例</h2>
  <label>端点</label>
  <select id="add-endpoint">
    <option value="">自动（依次尝试所有端点）</option>
  </select>
  <label>或手动输入端点（host 或 host:port）</label>
  <input id="add-manual" placeholder="例如 162.159.198.2:443" size="34">
  <div style="margin-top:18px;display:flex;gap:8px;justify-content:flex-end">
    <button id="add-cancel">取消</button>
    <button class="primary" id="add-ok">创建并启动</button>
  </div>
</dialog>

<script>
const $ = id => document.getElementById(id);
let liveEndpoints = [];

async function api(path, method='GET'){
  const r = await fetch(path, {method});
  try { return await r.json(); } catch(e){ return {ok:false, error:String(e)}; }
}
function pill(s){ return '<span class="pill '+s+'">'+s+'</span>'; }

document.addEventListener('click', async ev => {
  const el = ev.target.closest('[data-act]');
  if(!el) return;
  const act = el.dataset.act, name = el.dataset.name || '';
  const q = name ? ('?name='+encodeURIComponent(name)) : '';
  if(act === 'use-endpoint'){
    $('add-manual').value = el.dataset.ep;
    $('dlg-add').showModal();
    return;
  }
  await api('/api/'+act+q, 'POST');
  refresh();
});
$('btn-scan').onclick = async () => { $('scan-state').textContent = '扫描中…'; await api('/api/scan','POST'); setTimeout(refresh, 400); };
$('btn-scan-stop').onclick = async () => { await api('/api/scan/stop','POST'); $('scan-state').textContent = '正在停止…'; refresh(); };
$('btn-add').onclick = () => { $('add-manual').value=''; $('dlg-add').showModal(); };
$('add-cancel').onclick = () => $('dlg-add').close();
$('add-ok').onclick = async () => {
  const manual = $('add-manual').value.trim();
  const chosen = manual || $('add-endpoint').value;
  let url = '/api/add';
  if(chosen) url += '?endpoint=' + encodeURIComponent(chosen);
  await api(url, 'POST');
  $('dlg-add').close();
  refresh();
};

async function refresh(){
  let data;
  try { data = await api('/api/status'); }
  catch(e){ $('summary').textContent = '后端无响应'; return; }

  $('rows').innerHTML = data.instances.map(i => {
    const err = i.error ? '<div class="sub">'+i.error+'</div>' : '';
    const running = i.status === 'running';
    return '<tr><td><b>'+i.name+'</b>'+err+'</td>'
      + '<td>'+pill(i.status)+'</td>'
      + '<td><code>'+i.port+'</code></td>'
      + '<td class="muted">'+(i.endpoint||'—')+'</td>'
      + '<td class="muted">'+(i.device||'—')+'</td>'
      + '<td class="muted">'+(i.tx||0)+' ↑ / '+(i.rx||0)+' ↓</td>'
      + '<td class="muted">'+(i.uptime_text||'—')+'</td>'
      + '<td><div class="row-actions">'
      + '<button class="tiny" data-act="restart" data-name="'+i.name+'">重启</button>'
      + (running
          ? '<button class="tiny danger" data-act="stop" data-name="'+i.name+'">停止</button>'
          : '<button class="tiny primary" data-act="start" data-name="'+i.name+'">启动</button>')
      + '<button class="tiny danger" data-act="remove" data-name="'+i.name+'">删除</button>'
      + '</div></td></tr>';
  }).join('') || '<tr><td colspan="8" class="muted">还没有实例</td></tr>';

  $('summary').textContent = data.running + ' / ' + data.total + ' 个实例在运行';
  const sum = (k) => data.instances.reduce((a,i)=>a+(i[k]||0),0);
  $('metrics').textContent = '累计隧道包 tx='+sum('tx')+' rx='+sum('rx')
    + '　SOCKS5 连接 累计='+sum('connections')+' 进行中='+sum('active');

  const scan = await api('/api/scan');
  $('btn-scan-stop').style.display = scan.scanning ? '' : 'none';
  $('btn-scan').style.display = scan.scanning ? 'none' : '';
  if(scan.scanning){
    $('scan-state').textContent = '扫描中… ' + (scan.scanned||0) + ' / ' + (scan.total||'?')
      + (scan.stop_requested ? '（正在停止…）' : '');
  } else if(scan.duration != null){
    $('scan-state').textContent = '可用 '+scan.live_count+' / '+scan.scanned
      + '，用时 '+scan.duration+'s';
  }
  liveEndpoints = scan.live || [];
  $('endpoints').innerHTML = liveEndpoints.length
    ? liveEndpoints.map(e =>
        '<span class="ep"><b>#'+(e.rank||'?')+'</b> <code>'+e.target+'</code>'
        + '<span class="muted">'+(e.transport||'')+' 丢包'+(e.loss!=null?e.loss:'?')+'% '
        + (e.latency!=null?Math.round(e.latency*1000)+'ms':'')+'</span>'
        + ((e.owners&&e.owners.length)
            ? '<span class="pill running">'+(e.owners.length>1?e.owners.length+' 个实例':e.owners[0])+'</span>'
            : '')
        + '<button class="tiny primary" data-act="use-endpoint" data-ep="'+e.target+'">用它建实例</button>'
        + '</span>'
      ).join('')
    : '<span class="sub">当前没有可用端点（可再扫一次，或在新建时手动指定）</span>';

  const sel = $('add-endpoint');
  const keep = sel.value;
  sel.innerHTML = '<option value="">自动（取排名最靠前的端点）</option>'
    + liveEndpoints.map(e => '<option value="'+e.target+'">#'+(e.rank||'?')+' '+e.target
        + ' — '+(e.transport||'')+' 丢包'+(e.loss!=null?e.loss:'?')+'%'
        + ((e.owners&&e.owners.length)?('（已有 '+e.owners.length+' 个实例）'):'')+'</option>').join('');
  sel.value = keep;
}
refresh(); setInterval(refresh, 2000);
</script></body></html>
"""


class WebUI:
    def __init__(
        self,
        pool: WarpPool,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        scanner: Optional[EndpointScanner] = None,
        on_add: Optional[Callable[[], None]] = None,
    ) -> None:
        self.pool = pool
        self.host = host
        self.port = port
        self.scanner = scanner
        self.on_add = on_add
        self.bound_port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        sockets = self._server.sockets or []
        if sockets:
            self.bound_port = sockets[0].getsockname()[1]
        log.info("web UI on http://%s:%d", self.host, self.bound_port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._server = None

    # ------------------------------------------------------------------ http
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        except Exception:  # noqa: BLE001
            writer.close()
            return
        try:
            head = request.decode("latin-1").split("\r\n")
            method, target, _ = head[0].split(" ", 2)
            headers = {}
            for line in head[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            length = int(headers.get("content-length") or 0)
            if length:
                await asyncio.wait_for(reader.readexactly(length), 10)

            parsed = urlparse(target)
            query = parse_qs(parsed.query)
            name = (query.get("name") or [""])[0]
            endpoint = (query.get("endpoint") or [""])[0]
            body, ctype, code = await self._route(method, parsed.path, name, endpoint)
        except Exception as exc:  # noqa: BLE001
            log.exception("web request failed")
            body, ctype, code = json.dumps({"ok": False, "error": str(exc)}), "application/json", 500

        payload = body.encode("utf-8") if isinstance(body, str) else body
        writer.write(
            f"HTTP/1.1 {code} OK\r\n".encode()
            + f"Content-Type: {ctype}; charset=utf-8\r\n".encode()
            + f"Content-Length: {len(payload)}\r\n".encode()
            + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
            + payload
        )
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        writer.close()

    async def _route(
        self, method: str, path: str, name: str, endpoint: str
    ) -> tuple[str, str, int]:
        if path in ("/", "/index.html"):
            return PAGE, "text/html", 200
        if path == "/api/status":
            return json.dumps(self.pool.status(), ensure_ascii=False), "application/json", 200
        if path == "/api/scan":
            if self.scanner is None:
                return json.dumps({"scanning": False, "scanned": 0, "live": [],
                                   "live_count": 0, "failures": {}, "duration": None,
                                   "error": "scanner disabled"}), "application/json", 200
            if method == "POST" and not self.scanner.scanning:
                asyncio.create_task(self.scanner.scan())
            state = self.scanner.state()
            ranked = self.pool.ranked_endpoints()
            if ranked:
                # best first, with rank and the instance pinned to each
                state["live"] = ranked
            return json.dumps(state, ensure_ascii=False), "application/json", 200
        if path == "/api/scan/stop":
            if self.scanner is not None:
                self.scanner.request_stop()
            return json.dumps({"ok": True, "stopping": True}), "application/json", 200

        if method != "POST":
            return json.dumps({"ok": False, "error": "use POST"}), "application/json", 405

        instance = self.pool.get(name) if name else None
        if path == "/api/start-all":
            asyncio.create_task(self.pool.start_all())
            return json.dumps({"ok": True, "action": "start-all"}), "application/json", 200
        if path == "/api/stop-all":
            asyncio.create_task(self.pool.stop_all())
            return json.dumps({"ok": True, "action": "stop-all"}), "application/json", 200
        if path == "/api/add":
            new = self.pool.add(endpoint or None)
            asyncio.create_task(new.start())
            return json.dumps({"ok": True, "name": new.name, "port": new.port,
                               "endpoint": new.endpoint or "auto"}), "application/json", 200
        if path == "/api/remove":
            if not instance:
                return json.dumps({"ok": False, "error": "unknown instance"}), "application/json", 404
            # pool.remove() notifies the owner, which persists the new list
            self.pool.remove(name)
            return json.dumps({"ok": True, "removed": name}), "application/json", 200
        if path in ("/api/start", "/api/stop", "/api/restart"):
            if not instance:
                return json.dumps({"ok": False, "error": "unknown instance"}), "application/json", 404
            action = path.rsplit("/", 1)[1]
            if action == "start":
                asyncio.create_task(instance.start())
            elif action == "stop":
                asyncio.create_task(instance.stop())
            else:
                asyncio.create_task(instance.restart())
            return json.dumps({"ok": True, "action": action, "name": name}), "application/json", 200
        return json.dumps({"ok": False, "error": "not found"}), "application/json", 404
