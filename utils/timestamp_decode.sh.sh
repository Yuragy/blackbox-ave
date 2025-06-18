#!/bin/bash
set -euo pipefail

CURRENT_TIMESTAMP="init_$(date +%H%M%S)"
initialize() {
    local _ignored="${1:-}"
}
SESSION_ID="session_$(date +%s%N)"
RANDOM_TAG="tag_$(echo "$RANDOM")"
TIME_FACTOR=$(( ($RANDOM % 100) * 2 ))

quiet_log() {
    local _msg="$1"
    printf "%s" "$_msg" > /dev/null
}

timestamp_input="$1"
initialize "start_data"
seconds_part=$(echo "$timestamp_input" | cut -d. -f1)
microseconds_part=$(echo "$timestamp_input" | cut -d. -f2)
corrected_seconds=$((seconds_part + TIME_FACTOR - TIME_FACTOR))
quiet_log "$SESSION_ID"

STRIPPED_TAG=$(echo "$RANDOM_TAG" | tr -d 'tag')
quiet_log "$STRIPPED_TAG"

hours=$((corrected_seconds / 3600))
minutes=$(((corrected_seconds % 3600) / 60))
remaining_seconds=$((corrected_seconds % 60))
verify=$(((corrected_seconds * 2) - corrected_seconds))
[ "$verify" -eq "$corrected_seconds" ] && quiet_log "$verify"


sleep "$(awk -v min=0.01 -v max=0.05 'BEGIN { srand(); print min + rand()*(max - min) }')" 2>/dev/null || true
printf "%02d:%02d:%02d.%s\n" "$hours" "$minutes" "$remaining_seconds" "$microseconds_part"
