"""Protocol/security/lifecycle tests. No scanning or Internet requests."""
import asyncio
import json
import math
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from main import create_app
from service import Controller, json_safe, load_settings

ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'unit-test-only-not-a-session-secret'
HOST = '127.0.0.1:8099'
ORIGIN = 'http://' + HOST


class FakeController:
    def __init__(self):
        self.commands = []
        self.started = self.closed = False

    async def start(self):
        self.started = True

    async def close(self):
        self.closed = True

    def snapshot(self):
        return {'type': 'snapshot', 'mode': 'real', 'private_marker': 'only-after-auth'}

    async def command(self, message):
        if message['action'] != 'calibrate':
            raise ValueError('Comando non valido')
        self.commands.append(message)
        return message['action']


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.controller = FakeController()
        self.client = TestClient(create_app(ROOT, {}, TOKEN, 8099, self.controller), base_url=ORIGIN)

    def test_host_and_security_headers(self):
        with self.client as client:
            response = client.get('/health')
            self.assertEqual(response.status_code, 200)
            self.assertIn("script-src 'self'", response.headers['content-security-policy'])
            self.assertEqual(response.headers['x-frame-options'], 'DENY')
            self.assertEqual(client.get('/health', headers={'Host': 'evil.example'}).status_code, 403)
            self.assertEqual(client.get('/openapi.json').status_code, 404)
            self.assertEqual(client.get('/data/settings.json').status_code, 404)
        self.assertTrue(self.controller.closed)

    def test_cross_origin_websocket_rejected(self):
        with self.client as client:
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect(f'ws://{HOST}/ws', headers={'Origin': 'https://evil.example'}):
                    self.fail('Origin esterna accettata')

    def test_missing_origin_rejected(self):
        with self.client as client:
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect(f'ws://{HOST}/ws'):
                    self.fail('Origin mancante accettata')

    def test_wrong_token_no_telemetry(self):
        with self.client as client:
            with client.websocket_connect(f'ws://{HOST}/ws', headers={'Origin': ORIGIN}) as ws:
                ws.send_json({'type': 'auth', 'token': 'incorrect'})
                with self.assertRaises(WebSocketDisconnect):
                    ws.receive_json()

    def test_unicode_auth_token_rejected_without_server_error(self):
        with self.client as client:
            with client.websocket_connect(f'ws://{HOST}/ws', headers={'Origin': ORIGIN}) as ws:
                ws.send_json({'type': 'auth', 'token': 'non-ascii-é'})
                with self.assertRaises(WebSocketDisconnect) as rejected:
                    ws.receive_json()
                self.assertEqual(rejected.exception.code, 1008)
        self.assertEqual(self.controller.commands, [])
        self.assertEqual(self.client.app.state.clients, 0)

    def test_authenticated_commands_and_input_errors(self):
        with self.client as client:
            with client.websocket_connect(f'ws://{HOST}/ws', headers={'Origin': ORIGIN}) as ws:
                ws.send_json({'type': 'auth', 'token': TOKEN})
                self.assertEqual(ws.receive_json()['private_marker'], 'only-after-auth')
                ws.send_json({'type': 'command', 'action': 'calibrate'})
                for _ in range(10):
                    reply = ws.receive_json()
                    if reply['type'] == 'ack':
                        break
                self.assertEqual(reply, {'type': 'ack', 'action': 'calibrate'})
                ws.send_text('not JSON')
                for _ in range(10):
                    reply = ws.receive_json()
                    if reply['type'] == 'error':
                        break
                self.assertEqual(reply['type'], 'error')
        self.assertEqual(len(self.controller.commands), 1)

    def test_oversized_auth_is_rejected(self):
        with self.client as client:
            with client.websocket_connect(f'ws://{HOST}/ws', headers={'Origin': ORIGIN}) as ws:
                ws.send_text('x' * 4097)
                with self.assertRaises(WebSocketDisconnect):
                    ws.receive_json()

    def test_binary_command_closes_cleanly(self):
        with self.client as client:
            with client.websocket_connect(f'ws://{HOST}/ws', headers={'Origin': ORIGIN}) as ws:
                ws.send_json({'type': 'auth', 'token': TOKEN})
                self.assertEqual(ws.receive_json()['type'], 'snapshot')
                ws.send_bytes(b'not a text command')
                with self.assertRaises(WebSocketDisconnect):
                    while True:
                        ws.receive_json()


class StateTests(unittest.TestCase):
    def test_cancelled_workers_do_not_skip_remaining_cleanup(self):
        async def exercise():
            service = Controller(ROOT, dict(origin=None, interface=None, hz=10, mode='real', capture=False))
            worker = asyncio.create_task(asyncio.sleep(60))
            scan = asyncio.create_task(asyncio.sleep(60))
            worker.cancel()
            scan.cancel()
            service._tasks = [worker]
            service._scan_task = scan
            with patch.object(service.capture, 'stop') as capture_stop, \
                 patch.object(service, '_stop_engine', new_callable=AsyncMock) as engine_stop, \
                 patch.object(service.geo, 'close', wraps=service.geo.close) as geo_close:
                await service.close()
                capture_stop.assert_called_once()
                engine_stop.assert_awaited_once()
                geo_close.assert_called_once()
            self.assertTrue(worker.cancelled())
            self.assertTrue(scan.cancelled())
            self.assertTrue(service._stop.is_set())
            self.assertTrue(service._scan_stop.is_set())
        asyncio.run(exercise())

    def test_cancelling_close_finishes_cleanup_and_preserves_cancellation(self):
        async def exercise():
            service = Controller(ROOT, dict(origin=None, interface=None, hz=10, mode='real', capture=False))
            release = asyncio.Event()
            worker = asyncio.create_task(release.wait())
            service._tasks = [worker]
            with patch.object(service.capture, 'stop') as capture_stop, \
                 patch.object(service, '_stop_engine', new_callable=AsyncMock) as engine_stop, \
                 patch.object(service.geo, 'close', wraps=service.geo.close) as geo_close:
                closing = asyncio.create_task(service.close())
                while service._close_task is None:
                    await asyncio.sleep(0)
                closing.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await closing
                capture_stop.assert_called_once()
                engine_stop.assert_awaited_once()
                geo_close.assert_called_once()
            self.assertTrue(closing.cancelled())
            self.assertTrue(worker.done())
            self.assertFalse(worker.cancelled())
            self.assertTrue(service._close_task.done())
        asyncio.run(exercise())

    def test_nonfinite_json(self):
        self.assertEqual(json_safe({'x': [math.nan, math.inf]}), {'x': [None, None]})

    def test_real_only_and_no_manual_origin(self):
        async def run():
            service = Controller(ROOT, dict(interface=None, hz=10, mode='real', capture=False))
            try:
                for msg in ({'action':'mode','value':'demo'}, {'action':'origin','lat':1,'lon':2}):
                    with self.assertRaises(ValueError):
                        await service.command(msg)
                self.assertIsNone(service.snapshot()['origin'])
                self.assertEqual(service.snapshot()['devices'], [])
            finally:
                await service.close()
        asyncio.run(run())

    def test_no_hardware_no_fabricated_fallback(self):
        async def run():
            service = Controller(ROOT, dict(interface=None, hz=10, mode='real', capture=False))
            try:
                await service.start()
                await asyncio.sleep(.05)
                state=service.snapshot()
                for key in ('devices','connections','events'):
                    self.assertEqual(state[key], [])
                self.assertIsNone(state['telemetry'])
                self.assertIsNone(state['origin'])
            finally:
                await service.close()
        with patch('service.discover_network',side_effect=RuntimeError('no hardware')), patch('service.host_connections',return_value=([],[])):
            asyncio.run(run())

    def test_stale_samples_never_keep_live_alarm(self):
        import time
        async def run():
            service=Controller(ROOT,dict(interface=None,hz=10,mode='real',capture=False))
            service.telemetry=dict(timestamp=time.monotonic()-5,rssi_dbm=-50,rf_perturbation=True,intensity=100,source='test',warning='')
            service.connections=[{'remote_ip':'1.1.1.1'}]
            service._connections_received=time.monotonic()-20
            try:
                state=service.snapshot()
                self.assertIsNone(state['telemetry']['rssi_dbm'])
                self.assertIsNone(state['telemetry']['rf_perturbation'])
                self.assertEqual(state['connections'],[])
                self.assertEqual(state['events'],[])
            finally:
                await service.close()
        asyncio.run(run())

    def test_settings_migrate_demo_and_discard_typed_coordinates(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'settings.json'
            self.assertEqual(load_settings(path)['mode'],'real')
            path.write_text('{"mode":"demo","origin":{"lat":1,"lon":2}}')
            settings=load_settings(path)
            self.assertEqual(settings['mode'],'real')
            self.assertNotIn('origin',settings)
            path.write_text('{"hz":2}')
            with self.assertRaises(ValueError): load_settings(path)

if __name__ == '__main__':
    unittest.main()
