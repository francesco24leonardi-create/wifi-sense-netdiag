"""Build a self-contained Windows executable with PyInstaller on Windows."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    if sys.platform != 'win32':
        raise SystemExit('La build .exe richiede Windows. Su Linux usare start_linux.sh.')
    args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile',
            '--windowed', '--name', 'WiFi-Sense-NetDiag', '--distpath', str(ROOT/'dist'),
            '--workpath', str(ROOT/'build'), '--specpath', str(ROOT/'build'),
            '--runtime-hook', str(ROOT/'frozen_logging.py')]
    for directory in ('static', 'data', 'licenses'):
        args += ['--add-data', f'{ROOT/directory}:{directory}']
    for name in ('asset_manifest.json', 'README.md'):
        args += ['--add-data', f'{ROOT/name}:.']
    for package in ('webview', 'pythonnet', 'clr_loader'):
        args += ['--collect-data', package]
    for package in ('uvicorn', 'websockets', 'zeroconf', 'bleak', 'winrt'):
        args += ['--collect-all', package]
    for module in ('clr', 'webview.platforms.winforms', 'webview.platforms.edgechromium', 'scapy.layers.l2', 'scapy.arch.windows'):
        args += ['--hidden-import', module]
    args += [str(ROOT/'main.py')]
    subprocess.run(args, cwd=ROOT, check=True)
    print(ROOT/'dist/WiFi-Sense-NetDiag.exe')


if __name__ == '__main__':
    main()
