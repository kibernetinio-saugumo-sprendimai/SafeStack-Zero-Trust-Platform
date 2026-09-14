"""Localhost-only dashboard and read-only JSON API."""
import html, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .store import Store

def snapshot(store):
    devices=[dict(x) for x in store.db.execute('SELECT * FROM devices ORDER BY name')]
    policies=[dict(x) for x in store.db.execute('SELECT * FROM policies ORDER BY id')]
    decisions=[dict(x) for x in store.db.execute('SELECT * FROM decisions ORDER BY id DESC LIMIT 100')]
    return {'devices':devices,'policies':policies,'decisions':decisions}

def page(data):
    esc=lambda x:html.escape(str(x))
    cards=''.join(f"<article><b>{esc(k.title())}</b><strong>{len(v)}</strong></article>" for k,v in data.items())
    rows=''.join(f"<tr><td>{esc(d.get('subject'))}</td><td>{esc(d.get('resource'))}</td><td class={'ok' if d.get('allowed') else 'bad'}>{'ALLOW' if d.get('allowed') else 'DENY'}</td><td>{esc(d.get('reason'))}</td></tr>" for d in data['decisions'][:20])
    return f'''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SafeStack Zero Trust</title><style>body{{margin:0;background:#0b1020;color:#e8eefc;font:15px system-ui}}main{{max-width:1100px;margin:auto;padding:36px}}h1{{letter-spacing:.04em}}.accent{{color:#5eead4}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}article,section{{background:#121a30;border:1px solid #263657;border-radius:12px;padding:18px}}strong{{display:block;font-size:32px;margin-top:8px}}table{{width:100%;border-collapse:collapse}}td,th{{padding:10px;border-bottom:1px solid #263657;text-align:left}}.ok{{color:#5eead4}}.bad{{color:#fb7185}}small{{color:#91a4c5}}</style><main><h1>SafeStack <span class="accent">Zero Trust</span></h1><small>Local security control plane · default deny · read-only dashboard</small><div class="grid">{cards}</div><section><h2>Recent decisions</h2><table><tr><th>Subject</th><th>Resource</th><th>Result</th><th>Reason</th></tr>{rows}</table></section></main>'''

def serve(db_path='zero-trust.db', host='127.0.0.1', port=8787):
    store=Store(db_path)
    class Handler(BaseHTTPRequestHandler):
        def send(self, body, content_type):
            raw=body.encode(); self.send_response(200); self.send_header('Content-Type',content_type); self.send_header('Content-Length',str(len(raw))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            path=urlparse(self.path).path
            if path=='/health': self.send(json.dumps({'status':'ok','service':'safestack-zero-trust'}),'application/json'); return
            data=snapshot(store)
            if path=='/api/snapshot': self.send(json.dumps(data,default=str),'application/json'); return
            if path=='/': self.send(page(data),'text/html; charset=utf-8'); return
            self.send_error(404)
        def log_message(self,*args): pass
    ThreadingHTTPServer((host,port),Handler).serve_forever()
