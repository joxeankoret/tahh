#!/bin/bash

MULTIAV_ADDR=ip-of-multiav:8080
MULTIAV_PATH=/path/to/multiav
MULTIAV_TOOL=$MULTIAV_PATH/multiav-client.py
CLOAK_PATH=./peCloak.py

if [ $# -lt 1 ]; then
  echo "Usage: $0 <pefile>"
  exit 0
fi

sample=$1

while [ 1 ]
do
  echo "[+] Mutating the input PE file..."
  $CLOAK_PATH -a -o test.exe $sample
  echo "[+] Testing antivirus detection..."
  if $MULTIAV_TOOL $MULTIAV_ADDR test.exe -f; then
    echo "[i] Sample `md5sum test.exe` undetected!"
    break
  else
    echo "[!] Sample still detected, continuing..."
  fi
done
