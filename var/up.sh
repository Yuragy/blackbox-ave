#!/bin/bash
OBF_UNUSED="qwertyXYZ"
insmod=$(which insmod)
if [ -z "$insmod" ]; then
  echo "insmod not found, skipping"
  exit 1
fi

$insmod "$1" >/dev/null 2>&1
echo "$OBF_UNUSED  /loaded"
