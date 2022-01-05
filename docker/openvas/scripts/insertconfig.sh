#!/bin/bash
CONFIG=/etc/openvas/cbox-OpenVAS.xml
LOCK=/data/imported_CyberHack_Config
if [ ! -f "$LOCK" ]; then
  python3 -m venv .venv-openvas
  source .venv-openvas/bin/activate
  pip install python-gvm
  python3 /root/config.py
  deactivate
  echo "OpenVAS Config Full and Fast without Default Account Check and Bruteforce imported."
  rm -r .venv-openvas
  touch $LOCK
fi
