"""Writable per-user state; packaged resources remain read-only."""
import os
from pathlib import Path
import sys


def user_data(create=False):
    base = Path(os.environ.get('LOCALAPPDATA', Path.home())) if sys.platform == 'win32' else Path(os.environ.get('XDG_DATA_HOME', Path.home()/'.local/share'))
    path = Path(os.environ.get('WIFI_SENSE_DATA_DIR', base / 'WiFiSenseNetDiag'))
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path
