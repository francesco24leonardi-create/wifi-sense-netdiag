"""Read-only radio capabilities and connected-link metadata. No band changes."""
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import time

from netio import run_command


def interfaces():
    rows = []
    import psutil
    for name in psutil.net_if_addrs():
        try:
            index = socket.if_nametoindex(name)
        except OSError:
            index = None
        wireless = (Path('/sys/class/net', name, 'wireless').exists()
                    if sys.platform.startswith('linux') else None)
        rows.append(dict(name=name, index=index, wireless=wireless))
    return rows


def band_for_frequency(value):
    if value is None:
        return None
    if 2400 <= value <= 2500:
        return '2.4 GHz'
    if 4900 <= value < 5925:
        return '5 GHz'
    if 5925 <= value <= 7125:
        return '6 GHz'
    return None


def parse_link(text):
    result = dict(frequency_mhz=None, band=None, bssid=None, ssid=None, channel=None)
    for line in text.splitlines():
        match = re.search(r'Connected to\s+([a-fA-F0-9:]{17})', line)
        if match:
            result['bssid'] = match[1].lower()
        if ':' not in line:
            continue
        key, value = (s.strip() for s in line.split(':', 1))
        if key.lower() in ('freq', 'frequency'):
            number = re.search(r'\d+', value)
            if number:
                result['frequency_mhz'] = int(number[0])
        if key.lower() in ('channel', 'canale') and value.isdigit():
            result['channel'] = int(value)
        if key.lower() == 'ssid':
            result['ssid'] = value[:128]
        if key.lower() == 'bssid' and re.fullmatch(r'[a-fA-F0-9:]{17}', value):
            result['bssid'] = value.lower()
        if key.lower() in ('band', 'banda'):
            match = re.search(r'(2[.,]4|5|6)\s*GHz', value, re.I)
            if match:
                result['band'] = match[1].replace(',', '.') + ' GHz'
    result['band'] = band_for_frequency(result['frequency_mhz']) or result['band']
    # A channel alone is ambiguous with 6 GHz: never assume 2.4 GHz.
    return result


def link_status(network):
    result = dict(interface=network.interface, observed_at=time.time(), required_band='2.4 GHz')
    try:
        if sys.platform == 'win32':
            output = run_command(['netsh', 'wlan', 'show', 'interfaces'], 4)
            # netsh lists all adapters; select the exact interface block.
            blocks = re.split(r'(?mi)^\s*(?:Name|Nome)\s*:\s*', output)
            selected = next((block for block in blocks[1:]
                             if block.splitlines()[0].strip().casefold() == network.interface.casefold()), '')
            if not selected:
                raise RuntimeError('Interfaccia non presente in netsh WLAN; verificare WLAN AutoConfig e posizione Windows.')
            result.update(parse_link(selected))
        else:
            result.update(parse_link(run_command(['iw', 'dev', network.interface, 'link'], 2)))
        result['eligible'] = result.get('band') == '2.4 GHz'
        result['message'] = ('Link 2,4 GHz verificato.' if result['eligible'] else
            'Collegare questa scheda al SSID 2,4 GHz del router; banda attuale: ' + (result.get('band') or 'non disponibile') + '.')
    except Exception as exc:
        result.update(eligible=False, band=None, message=str(exc)[:400])
    return result


def diagnostics():
    try:
        adapters = interfaces()
    except OSError:
        adapters = []
    return dict(platform=sys.platform, cpu_logical=os.cpu_count(), interfaces=adapters,
        requested_band='2.4 GHz', software_polling_range_hz=[10, 50],
        hardware_max_sample_hz=None, hardware_limit_note='Il driver non espone una frequenza massima certificata. Frequenza effettiva misurata in telemetria.',
        csi_available=False, human_detection_available=False,
        sensing_note='Rilevazione di perturbazioni RSSI; per presenza umana servono sensori CSI compatibili e validazione sul posto.',
        tools={name: bool(shutil.which(name)) for name in ('iw', 'nmcli', 'ip', 'ping', 'netsh')})
