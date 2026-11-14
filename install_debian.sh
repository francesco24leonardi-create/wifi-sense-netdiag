#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip python3-gi python3-gi-cairo \
  gir1.2-gtk-3.0 gir1.2-webkit2-4.1 iproute2 iputils-ping iw network-manager bluez geoclue-2.0
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python setup_offline.py --verify
printf '\nPronto: bash start_linux.sh --interface wlan0\nControllare il vero nome della scheda con: iw dev\n'
