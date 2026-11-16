#!/bin/bash
# Helpers for matching only previously selected interfaces. No device serials are stored.

decode_port_spec() {
  port_iface=$1
  port_kind=fixed
  case "$1" in
    *@mobile) port_iface=${1%@mobile}; port_kind=mobile ;;
  esac
  [[ "$port_iface" =~ ^(en|ap|feth)[0-9]+$ ]] || return 1
  [ "$port_kind" != mobile ] || [[ "$port_iface" =~ ^en[0-9]+$ ]]
}

resolve_mobile_iface() {
  local identity=$1 snapshot=$2
  [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$snapshot" | /usr/bin/awk -v wanted="$identity" '
    $2 == wanted && $1 ~ /^en[0-9]+$/ { count++; found=$1 }
    END { if (count == 1) print found; else exit 1 }
  '
}

interface_attach_allowed() {
  local iface=$1 source=$2 default_iface=$3 has_external_ipv4=$4 other_bridge=$5
  [[ "$iface" =~ ^(en|ap|feth)[0-9]+$ ]] || return 1
  [ "$iface" != "$source" ] && [ "$iface" != "$default_iface" ] &&
    [ "$has_external_ipv4" = 0 ] && [ "$other_bridge" = 0 ]
}
