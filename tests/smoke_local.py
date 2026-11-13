"""Loopback integration; hardware unavailability injected only in this test."""
import json
from pathlib import Path
import sys
import threading
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from main import LocalServer
from service import load_settings
from websockets.sync.client import connect

baseline={t.ident for t in threading.enumerate()}
with patch('service.discover_network',side_effect=RuntimeError('test unavailable')), patch('service.host_connections',return_value=([],[])):
    server=LocalServer(ROOT,load_settings(ROOT/'data/settings.json'))
    try:
        server.start()
        with connect(f'ws://127.0.0.1:{server.port}/ws',origin=f'http://127.0.0.1:{server.port}',proxy=None) as ws:
            ws.send(json.dumps({'type':'auth','token':server.token}))
            for _ in range(20):
                message=json.loads(ws.recv(timeout=3))
                assert message['mode']=='real'
                assert message['devices']==message['connections']==message['events']==[]
                assert message['origin'] is None and message['telemetry'] is None
            ws.send(json.dumps({'type':'command','action':'mode','value':'demo'}))
            while json.loads(ws.recv(timeout=3))['type']!='error': pass
        print('PASS: 20 snapshots; unavailable data remains absent; simulation rejected')
    finally:
        server.stop()
assert not [t for t in threading.enumerate() if t.ident not in baseline and not t.daemon]
print('PASS: no remaining non-daemon workers')
