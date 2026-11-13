"""Loopback-only FastAPI/WebSocket server hosted in a pywebview desktop window."""
from __future__ import annotations
import argparse
import asyncio
from contextlib import asynccontextmanager, suppress
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
import webbrowser

os.environ['OTEL_SDK_DISABLED'] = 'true'

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from service import Controller, load_settings

ROOT = Path(__file__).resolve().parent


def create_app(root: Path, settings: dict, token: str, port: int, controller=None) -> FastAPI:
    """No API is exposed to the LAN, no CORS and no unauthenticated telemetry."""
    controller = controller or Controller(root, settings)
    host = f'127.0.0.1:{port}'
    origin = f'http://{host}'

    @asynccontextmanager
    async def lifespan(app):
        try:
            await controller.start()
            yield
        finally:
            await controller.close()

    app = FastAPI(title='WiFi-Sense & NetDiag 3D', docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.controller = controller
    app.state.clients = 0

    @app.middleware('http')
    async def local_only(request: Request, call_next):
        if request.headers.get('host') != host:
            return JSONResponse({'error': 'Host non autorizzato'}, status_code=403)
        response = await call_next(request)
        response.headers.update({
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                f"connect-src 'self' ws://{host}; font-src 'self'; "
                "worker-src 'self' blob:; object-src 'none'; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'",
            'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        })
        return response

    @app.get('/')
    async def index():
        return FileResponse(root / 'static/index.html', media_type='text/html')

    @app.get('/health')
    async def health():
        return {'ok': True, 'application': 'WiFi-Sense & NetDiag 3D'}

    app.mount('/static', StaticFiles(directory=root / 'static'), name='static')

    @app.websocket('/ws')
    async def websocket(ws: WebSocket):
        if ws.headers.get('host') != host or ws.headers.get('origin') != origin or app.state.clients >= 4:
            await ws.close(code=1008)
            return
        app.state.clients += 1
        try:
            await ws.accept()
        except BaseException:
            app.state.clients -= 1
            raise
        producer = None
        receive = None
        send_lock = asyncio.Lock()

        async def send(value):
            async with send_lock:
                await ws.send_json(value)

        async def stream():
            while True:
                # Latest snapshot only: slow clients cannot create an unbounded queue.
                await asyncio.wait_for(send(controller.snapshot()), timeout=3)
                await asyncio.sleep(.1)

        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=5)
            if len(raw) > 4096:
                await ws.close(code=1009)
                return
            auth = json.loads(raw)
            if (not isinstance(auth, dict) or auth.get('type') != 'auth'
                    or not isinstance(auth.get('token'), str)
                    or not auth['token'].isascii()
                    or not secrets.compare_digest(auth['token'], token)):
                await ws.close(code=1008)
                return
            producer = asyncio.create_task(stream(), name='ui-snapshots')
            window_started, count = time.monotonic(), 0
            while True:
                # Check producer failures without accepting a permanently dead client.
                receive = asyncio.create_task(ws.receive_text())
                done, _ = await asyncio.wait((receive, producer), return_when=asyncio.FIRST_COMPLETED)
                if producer in done:
                    receive.cancel()
                    with suppress(asyncio.CancelledError):
                        await receive
                    producer.result()
                    break
                raw = receive.result()
                if len(raw) > 4096:
                    await ws.close(code=1009)
                    break
                now = time.monotonic()
                if now - window_started >= 1:
                    window_started, count = now, 0
                count += 1
                if count > 10:
                    await ws.close(code=1008)
                    break
                try:
                    command = json.loads(raw)
                    if not isinstance(command, dict) or command.get('type') != 'command':
                        raise ValueError('Messaggio di comando non valido')
                    action = await controller.command(command)
                    await send({'type': 'ack', 'action': action})
                except (ValueError, OSError, RuntimeError) as exc:
                    await send({'type': 'error', 'message': str(exc)[:800]})
        except (WebSocketDisconnect, asyncio.TimeoutError, ValueError, RuntimeError, KeyError):
            with suppress(RuntimeError, WebSocketDisconnect):
                await ws.close(code=1008)
        finally:
            app.state.clients -= 1
            if receive is not None:
                receive.cancel()
                with suppress(asyncio.CancelledError, WebSocketDisconnect, RuntimeError, KeyError):
                    await receive
            if producer is not None:
                producer.cancel()
                with suppress(asyncio.CancelledError, WebSocketDisconnect, RuntimeError, asyncio.TimeoutError):
                    await producer

    return app


class LocalServer:
    def __init__(self, root: Path, settings: dict, port: int = 0):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Do not enable SO_REUSEADDR on Windows: keep exclusive ownership of the port.
        self.socket.bind(('127.0.0.1', port))
        self.port = self.socket.getsockname()[1]
        self.token = secrets.token_urlsafe(32)
        self.url = f'http://127.0.0.1:{self.port}/#token={self.token}'
        app = create_app(root, settings, self.token, self.port)
        self.controller = app.state.controller
        self.server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=self.port,
            log_level='warning', access_log=False, ws_max_size=8192,
            timeout_graceful_shutdown=20, lifespan='on'))
        self.thread = threading.Thread(target=self.server.run, kwargs={'sockets': [self.socket]},
                                       name='local-asgi', daemon=False)

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + 25
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > deadline:
                self.stop()
                raise RuntimeError('Il backend locale non si è avviato')
            time.sleep(.05)

    def stop(self) -> None:
        self.server.should_exit = True
        if self.thread.is_alive():
            self.thread.join(timeout=35)
        self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError('Un driver o una scansione non ha ancora terminato la chiusura')


def check_assets(root: Path) -> None:
    from setup_offline import install_asset
    manifest = json.loads((root / 'asset_manifest.json').read_text(encoding='utf-8'))
    for spec in manifest['assets']:
        if spec['path'].startswith('static/'):
            install_asset(spec, root=root, verify_only=True)
    if not (root / 'static/index.html').is_file():
        raise FileNotFoundError('Interfaccia mancante: static/index.html')


def native_ui_dispatcher(window):
    """Invoke WinRT permission creation on the foreground WinForms UI thread.

    No permission is granted here: Windows handles the user's consent.
    The callable returns its WinRT operation to be awaited by the provider.
    """
    async def dispatch(factory):
        loop = asyncio.get_running_loop()
        result = loop.create_future()

        def deliver(value=None, error=None):
            if not result.done():
                if error is not None:
                    result.set_exception(error)
                else:
                    result.set_result(value)

        def invoke():
            try:
                value = factory()
            except Exception as exc:
                loop.call_soon_threadsafe(deliver, None, exc)
            else:
                loop.call_soon_threadsafe(deliver, value, None)

        native = getattr(window, 'native', None)
        if native is None:
            raise RuntimeError('Finestra desktop non pronta: riprovare dopo il caricamento')
        from System import Action
        native.BeginInvoke(Action(invoke))
        return await asyncio.wait_for(result, 10)
    return dispatch


def main() -> None:
    parser = argparse.ArgumentParser(description='WiFi-Sense & NetDiag · desktop 3D locale')
    parser.add_argument('--real', action='store_true', help='Solo osservazioni reali (sempre attivo)')
    parser.add_argument('--interface', help='Interfaccia IPv4 da usare, ad esempio Wi-Fi o wlan0')
    parser.add_argument('--hz', type=float, help='Frequenza richiesta RSSI/ICMP, 10–50 Hz')
    parser.add_argument('--capture', action='store_true', help='Abilita cattura passiva IPv4 in modalità reale')
    parser.add_argument('--location-provider', choices=('system', 'gpsd'),
                        help='Posizione da sistema (può usare Internet) o GPSD locale')
    parser.add_argument('--port', type=int, default=0, help='Porta loopback; 0 sceglie una porta libera')
    parser.add_argument('--browser', action='store_true', help='Apri nel browser locale anziché pywebview')
    parser.add_argument('--headless', action='store_true', help='Solo server locale; stampa URL di sessione')
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error('Porta non valida')
    if args.hz is not None and (not math_is_hz(args.hz)):
        parser.error('--hz deve essere compreso tra 10 e 50')
    server = None
    try:
        check_assets(ROOT)
        settings = load_settings(ROOT / 'data/settings.json')
        settings['mode'] = 'real'
        if args.location_provider:
            settings['location_provider'] = args.location_provider
        if args.interface:
            settings['interface'] = args.interface
        if args.hz is not None:
            settings['hz'] = args.hz
        if args.capture:
            settings['capture'] = True
        server = LocalServer(ROOT, settings, args.port)
        server.start()
        if args.headless or args.browser:
            print(f'Sessione locale: {server.url}', flush=True)
            if args.browser:
                webbrowser.open(server.url)
            while server.thread.is_alive():
                server.thread.join(timeout=.25)
        else:
            import webview
            window = webview.create_window('WiFi-Sense & NetDiag · Osservazioni reali 3D', server.url,
                width=1440, height=960, min_size=(1100, 760), background_color='#050b12', text_select=True)
            if sys.platform == 'win32':
                server.controller.location.ui_dispatch = native_ui_dispatcher(window)
            webview.start(gui='edgechromium' if sys.platform == 'win32' else None,
                          debug=False, private_mode=True)
    except KeyboardInterrupt:
        return
    except Exception as exc:
        print(f'Avvio non riuscito: {exc}', file=sys.stderr)
        print('Verificare README.md, dipendenze, WebView2/WebKit e python setup_offline.py --verify.', file=sys.stderr)
        raise SystemExit(1) from exc
    finally:
        if server is not None:
            server.stop()


def math_is_hz(value: float) -> bool:
    import math
    return math.isfinite(value) and 10 <= value <= 50


if __name__ == '__main__':
    main()
