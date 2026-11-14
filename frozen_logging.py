"""Supply file streams to libraries in a console-free executable."""
import os
from pathlib import Path
import sys

if sys.stdout is None or sys.stderr is None:
    directory = Path(os.environ.get('WIFI_SENSE_DATA_DIR', Path(os.environ.get('LOCALAPPDATA', Path.home()))/'WiFiSenseNetDiag'))
    directory.mkdir(parents=True, exist_ok=True)
    stream = (directory/'application.log').open('w', encoding='utf-8', buffering=1)
    sys.stdout = sys.stdout or stream
    sys.stderr = sys.stderr or stream
