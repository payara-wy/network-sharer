#!/bin/bash
# Selected interfaces are used as downstream ports.
set -u
umask 077
SCRIPT_DIR=$(/usr/bin/dirname "$0")
CONTENTS=$(/usr/bin/dirname "$SCRIPT_DIR")
DAEMON="$CONTENTS/MacOS/standalone_bridge"
GATEWAY="$CONTENTS/MacOS/socks_gateway"
IDENTITY="$CONTENTS/MacOS/mobile_identity"
SUPERVISOR="$CONTENTS/MacOS/session_supervisor"
SUBNET_GUARD="$CONTENTS/MacOS/subnet_guard"
LEASE_STORE="$CONTENTS/MacOS/lease_store"
RECONNECT_HELPERS="$SCRIPT_DIR/reconnect_helpers.sh"


die() { printf '%s\n' "$*" >&2; exit 1; }
valid_dns() {
  local a b c d
  [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<< "$1"
  (( 10#$a > 0 && 10#$a < 224 && 10#$a != 127 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 ))
}
[ "$(/usr/bin/id -u)" = 0 ] || die '需要管理员权限。'
[ -f "$RECONNECT_HELPERS" ] || die '应用组件缺失。'
. "$RECONNECT_HELPERS"
[ "$#" -ge 1 ] || die '缺少操作。'
mode=$1; shift

recover_interfaces() {
  local session=$1 kind name expected expected_index extra info observed observed_index owner mode links
  case "$session" in /private/tmp/lanproxy.????????) ;; *) return 1;; esac
  [ -d "$session" ] && [ ! -L "$session" ] && [ -f "$session/session.marker" ] && [ ! -L "$session/session.marker" ] || return 1
  read -r owner mode < <(/usr/bin/stat -f '%u %Lp' "$session" 2>/dev/null) || return 1
  [ "$owner" = 0 ] && [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 0022) == 0 )) || return 1
  [ "$(/bin/cat "$session/session.marker" 2>/dev/null)" = 'NetworkSharerSession/1' ] || return 1
  [ -f "$session/interfaces" ] && [ ! -L "$session/interfaces" ] || return 0
  read -r owner mode links < <(/usr/bin/stat -f '%u %Lp %l' "$session/interfaces" 2>/dev/null) || return 1
  [ "$owner" = 0 ] && [ "$links" = 1 ] && [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 0022) == 0 )) || return 1
  while read -r kind name expected expected_index extra; do
    case "$kind:$name" in bridge:bridge[0-9]*|feth:feth[0-9]*) ;; *) continue;; esac
    [[ "$name" =~ ^(bridge|feth)[0-9]+$ && "$expected" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || continue
    [ -z "$extra" ] || continue
    info=$(/sbin/ifconfig -v "$name" 2>/dev/null) || continue
    observed=$(printf '%s\n' "$info" | /usr/bin/awk '/^[[:space:]]*ether /{print $2; exit}')
    [ "$observed" = "$expected" ] || continue
    if [ -n "$expected_index" ]; then
      [[ "$expected_index" =~ ^[0-9]+$ ]] || continue
      observed_index=$(printf '%s\n' "$info" | /usr/bin/awk 'NR==1 { for(i=1;i<NF;i++) if($i=="index") {print $(i+1); exit} }')
      [ "$observed_index" = "$expected_index" ] || continue
    fi
    /sbin/ifconfig "$name" destroy 2>/dev/null || true
  done < <(/usr/bin/tail -r "$session/interfaces")
}

if [ "$mode" = _recover ]; then
  [ "$#" = 1 ] || exit 1
  recover_interfaces "$1"
  exit
fi

if [ "$mode" = launch ]; then
  [ "$#" -ge 7 ] && [ "$#" -le 15 ] || die '需要用户编号、应用进程、Wi-Fi、连接模式和 DNS。'
  owner=$1; gui_pid=$2; source=$3; route_mode=$4; proxy_port=$5; dns_server=$6; dns_secondary=$7; shift 7
  [[ "$owner" =~ ^[0-9]+$ ]] || die '用户编号无效。'
  [[ "$gui_pid" =~ ^[0-9]+$ ]] && [ "$gui_pid" -gt 1 ] || die '应用进程无效。'
  [[ "$source" =~ ^en[0-9]+$ ]] || die 'Wi-Fi 接口无效。'
  [[ "$route_mode" = direct || "$route_mode" = socks5 ]] || die '连接模式无效。'
  [[ "$proxy_port" =~ ^[0-9]{1,5}$ ]] && [ "$proxy_port" -le 65535 ] || die '代理端口无效。'
  [ "$route_mode" = direct ] || [ "$proxy_port" -gt 0 ] || die '代理端口无效。'
  valid_dns "$dns_server" || die 'DNS 服务器地址无效。'
  [ "$dns_secondary" = '-' ] || valid_dns "$dns_secondary" || die '备用 DNS 服务器地址无效。'
  portlist=''; seen=' '
  for spec in "$@"; do
    decode_port_spec "$spec" || die '共享端口名称无效。'
    iface=$port_iface
    [ "$iface" != "$source" ] || die '上游与共享端口不能相同。'
    case "$seen" in *" $iface "*) die '共享端口重复。';; esac
    seen="$seen$iface "; portlist="${portlist:+$portlist,}$iface"
  done
  [ "$#" -gt 0 ] || [ "${NAPTD_LAN_PROXY_PORT:-0}" != 0 ] || die '请选择共享端口，或启用局域网代理。'
  if [ "${NAPTD_LAN_PROXY_PORT:-0}" != 0 ]; then
    [[ "$NAPTD_LAN_PROXY_PORT" =~ ^[0-9]{1,5}$ ]] && [ "$NAPTD_LAN_PROXY_PORT" -gt 0 ] && [ "$NAPTD_LAN_PROXY_PORT" -le 65535 ] || die '局域网代理端口无效。'
    [ "$NAPTD_LAN_PROXY_PORT" != "$proxy_port" ] || [ "$route_mode" = direct ] || die '局域网代理端口不能与本机上游代理端口相同。'
  fi
  for path in "$DAEMON" "$GATEWAY" "$IDENTITY" "$SUPERVISOR" "$SUBNET_GUARD" "$LEASE_STORE"; do
    [ -e "$path" ] || die '应用组件缺失。'
  done
  dir=$(/usr/bin/mktemp -d /private/tmp/lanproxy.XXXXXXXX) || exit 1
  /bin/chmod 711 "$dir" || exit 1
  printf 'NetworkSharerSession/1\n' > "$dir/session.marker" || exit 1
  printf '%s\n' "$gui_pid" > "$dir/session.owner" || exit 1
  printf 'WAIT\n' > "$dir/control" || exit 1
  /usr/sbin/chown "$owner" "$dir/control" || exit 1
  /bin/chmod 600 "$dir/control" || exit 1
  printf '\000\000' > "$dir/auth" || exit 1
  /usr/sbin/chown "$owner" "$dir/auth" || exit 1
  /bin/chmod 600 "$dir/auth" || exit 1
  if [ "${NAPTD_LAN_PROXY_PORT:-0}" != 0 ]; then
    printf '\000\000' > "$dir/lan-auth" || exit 1
    /usr/sbin/chown "$owner" "$dir/lan-auth" || exit 1
    /bin/chmod 600 "$dir/lan-auth" || exit 1
  fi
  printf 'state=starting\nphase=awaiting_config\nmessage=正在准备连接配置\nsource=%s\ninterfaces=%s\nmode=%s\ndns=%s\ndns_secondary=%s\n' "$source" "$portlist" "$route_mode" "$dns_server" "$dns_secondary" > "$dir/state"
  /bin/chmod 644 "$dir/state"
  "$SUPERVISOR" "$dir" "$0" "$owner" "$gui_pid" "$source" "$route_mode" "$proxy_port" "$dns_server" "$dns_secondary" "$@" >"$dir/controller.log" 2>&1 </dev/null &
  supervisor=$!
  started=''; i=0
  while [ "$i" -lt 100 ]; do
    [ ! -f "$dir/supervisor.status" ] || started=$(/bin/cat "$dir/supervisor.status" 2>/dev/null || true)
    [ -z "$started" ] || break
    kill -0 "$supervisor" 2>/dev/null || break
    /bin/sleep .1; i=$((i+1))
  done
  if [ "$started" != ready ]; then
    printf 'STOP\n' > "$dir/control" 2>/dev/null || true
    kill "$supervisor" 2>/dev/null || true
    wait "$supervisor" 2>/dev/null || true
    /bin/rm -rf "$dir"
    [ "$started" != busy ] || die '已有共享正在运行或仍在清理，请稍后重试。'
    die '无法启动共享会话，请重试。'
  fi
  printf '%s\n' "$dir"
  exit 0
fi

[ "$mode" = _run ] && [ "$#" -ge 7 ] || die '未知操作。'
dir=$1; gui_pid=$2; source=$3; route_mode=$4; proxy_port=$5; dns_server=$6; dns_secondary=$7; shift 7
case "$dir" in /private/tmp/lanproxy.????????) ;; *) die '运行目录无效。';; esac
lan_port=${NAPTD_LAN_PROXY_PORT:-0}
[[ "$lan_port" =~ ^[0-9]{1,5}$ ]] || die '局域网代理端口无效。'
[[ "$gui_pid" =~ ^[0-9]+$ ]] && [ "$gui_pid" -gt 1 ] || die '应用进程无效。'
[[ "$source" =~ ^en[0-9]+$ ]] || die 'Wi-Fi 接口无效。'
[[ "$route_mode" = direct || "$route_mode" = socks5 ]] || die '连接模式无效。'
[[ "$proxy_port" =~ ^[0-9]{1,5}$ ]] && [ "$proxy_port" -le 65535 ] || die '代理端口无效。'
valid_dns "$dns_server" || die 'DNS 服务器地址无效。'
[ "$dns_secondary" = '-' ] || valid_dns "$dns_secondary" || die '备用 DNS 服务器地址无效。'
declare -a original_ports port_kinds port_ids port_macs current_ports missing_counts
portcount=0; portlist=''; portmap=''
for spec in "$@"; do
  decode_port_spec "$spec" || die '共享端口名称无效。'
  original_ports[$portcount]=$port_iface
  port_kinds[$portcount]=$port_kind
  port_ids[$portcount]='-'
  port_macs[$portcount]='-'
  current_ports[$portcount]=$port_iface
  missing_counts[$portcount]=0
  portlist="${portlist:+$portlist,}$port_iface"
  portmap="${portmap:+$portmap,}$port_iface:$port_iface"
  portcount=$((portcount+1))
done
lan_ready=0; lan_state=''
daemon=''; gateway=''; bridge=''; endpoint=''; peer=''; bridge_index=''; bridge_mac=''; endpoint_index=''; endpoint_mac=''; peer_index=''; peer_mac=''; attached_list=''; clients=''; state='starting'; phase='awaiting_config'; message='正在准备连接配置'; net_uuid=''
write_state() {
  printf 'state=%s\nphase=%s\nmessage=%s\nsource=%s\ninterfaces=%s\nportmap=%s\nmode=%s\ndns=%s\ndns_secondary=%s\nbridge=%s\nclients=%s\nnetwork_uuid=%s\ndaemon_pid=%s\ngateway_pid=%s\nlan_port=%s\nlan_ready=%s\nlan_state=%s\n' "$state" "$phase" "$message" "$source" "$portlist" "$portmap" "$route_mode" "$dns_server" "$dns_secondary" "$bridge" "$clients" "$net_uuid" "$daemon" "$gateway" "$lan_port" "$lan_ready" "$lan_state" > "$dir/state.new"
  /bin/chmod 644 "$dir/state.new"
  /bin/mv -f "$dir/state.new" "$dir/state"
}
cleanup() {
  if [ -n "$bridge" ]; then
    for member in $attached_list; do /sbin/ifconfig "$bridge" deletem "$member" 2>/dev/null || true; done
  fi
  if [ -n "$daemon" ]; then /bin/kill -KILL "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; fi
  if [ -n "$gateway" ]; then /bin/kill -KILL "$gateway" 2>/dev/null || true; wait "$gateway" 2>/dev/null || true; fi
  recover_interfaces "$dir"
  /bin/rm -f "$dir/auth" "$dir/lan-auth" 2>/dev/null || true
  if [ "$state" != error ]; then state=stopped; message='共享已停止'; fi
  write_state
}
fail() { state=error; message=$1; write_state; exit 1; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
i=0; while [ "$i" -lt 200 ]; do
  [ -f "$dir/control" ] && [ ! -L "$dir/control" ] || fail '控制文件不可用。'
  command=$(/bin/cat "$dir/control" 2>/dev/null || true)
  [ "$command" != STOP ] || exit 0
  kill -0 "$gui_pid" 2>/dev/null || exit 0
  [ "$command" != READY ] || break
  /bin/sleep .2; i=$((i+1))
done
[ "$command" = READY ] || fail '等待连接配置超时。'
[ -f "$dir/auth" ] && [ ! -L "$dir/auth" ] || fail '认证配置不可用。'
/usr/sbin/chown 0:0 "$dir/auth" && /bin/chmod 600 "$dir/auth" || fail '无法保护认证配置。'
if [ "$lan_port" != 0 ]; then
  [ -f "$dir/lan-auth" ] && [ ! -L "$dir/lan-auth" ] || fail '局域网代理认证配置不可用。'
  /usr/sbin/chown 0:0 "$dir/lan-auth" && /bin/chmod 600 "$dir/lan-auth" || fail '无法保护局域网代理认证配置。'
fi
phase=launching; message='正在检查共享端口和网络环境'; write_state
/sbin/ifconfig "$source" >/dev/null 2>&1 || fail 'Wi-Fi 接口不存在。'
/sbin/ifconfig "$source" | /usr/bin/grep -Eq '^[[:space:]]*inet ' || fail '所选 Wi-Fi 没有 IPv4 地址。'
default_iface=$(/sbin/route -n get default 2>/dev/null | /usr/bin/awk '/interface:/{print $2; exit}')
before=$(/sbin/ifconfig -l)
for ((i=0; i<portcount; i++)); do
  iface=${original_ports[$i]}
  /sbin/ifconfig "$iface" >/dev/null 2>&1 || fail "共享端口 $iface 不存在。"
  [ "$iface" != "$source" ] || fail '上游与共享端口不能相同。'
  [ "$iface" != "$default_iface" ] || fail "共享端口 $iface 正在承载默认网络连接。"
  if /sbin/ifconfig "$iface" | /usr/bin/grep -E '^[[:space:]]*inet ' | /usr/bin/grep -vq 'inet 169\.254\.'; then
    fail "共享端口 $iface 已有 IPv4 地址。"
  fi
  for item in $before; do
    case "$item" in bridge*)
      if /sbin/ifconfig "$item" 2>/dev/null | /usr/bin/grep -Eq "member: ${iface}([[:space:]]|$)"; then fail "共享端口 $iface 已属于其他网络桥接。"; fi;;
    esac
  done
done
if [ "$portcount" -gt 0 ]; then
  "$SUBNET_GUARD" >/dev/null 2>&1 || fail '共享网段与现有网络接口冲突，或无法检查网络。'
  if /usr/sbin/netstat -rn -f inet | /usr/bin/awk '{print $1}' | /usr/bin/grep -Eq '^172\.30\.79(\.|/|$)'; then fail '共享网段已有路由。'; fi
fi
net_uuid=$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')
relay_secret=$(/usr/bin/uuidgen | /usr/bin/tr -d '-' | /usr/bin/tr '[:upper:]' '[:lower:]')
[[ "$relay_secret" =~ ^[0-9a-f]{32}$ ]] || fail '无法生成连接组件密钥。'
/bin/cp "$GATEWAY" "$dir/socks_gateway" || fail '无法复制连接组件。'
/bin/cp "$IDENTITY" "$dir/mobile_identity" || fail '无法复制设备识别组件。'
if [ "$portcount" -gt 0 ]; then
  /bin/mkdir -m 700 "$dir/runtime" || fail '无法准备转发组件。'
  for component in standalone_bridge libslirp.0.dylib libglib-2.0.0.dylib libpcre2-8.0.dylib libintl.8.dylib libiconv.2.dylib; do
    /bin/cp -p "$CONTENTS/MacOS/$component" "$dir/runtime/$component" || fail '无法复制转发组件。'
  done
fi
lease_path=''; lease_dir=''
if [ "$portcount" -gt 0 ]; then
  lease_path=$("$LEASE_STORE") || fail '无法安全准备 DHCP 租约目录。'
  [ "$lease_path" = '/private/var/db/com.local.lansharer/dhcp-leases.ini' ] || fail 'DHCP 租约路径无效。'
  lease_dir=$(/usr/bin/dirname "$lease_path")
fi
device_salt=$(/usr/bin/uuidgen | /usr/bin/tr -d '-' | /usr/bin/tr '[:upper:]' '[:lower:]')
[[ "$device_salt" =~ ^[0-9a-f]{32}$ ]] || fail '无法准备设备识别。'
needs_mobile=0
for ((i=0; i<portcount; i++)); do [ "${port_kinds[$i]}" != mobile ] || needs_mobile=1; done
mobile_snapshot=''
if [ "$needs_mobile" = 1 ]; then
  mobile_snapshot=$(/usr/bin/env NAPTD_DEVICE_SALT="$device_salt" "$dir/mobile_identity") || fail '无法识别 iPhone USB。'
fi
for ((i=0; i<portcount; i++)); do
  iface=${original_ports[$i]}
  if [ "${port_kinds[$i]}" = mobile ]; then
    identity=$(printf '%s\n' "$mobile_snapshot" | /usr/bin/awk -v name="$iface" '$1 == name { count++; found=$2 } END { if (count == 1) print found }')
    [[ "$identity" =~ ^[0-9a-f]{64}$ ]] || fail '无法识别所选 iPhone，请重新连接后再试。'
    port_ids[$i]=$identity
  else
    mac=$(/sbin/ifconfig "$iface" | /usr/bin/awk '/^[[:space:]]*ether /{print $2; exit}')
    [[ "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] && port_macs[$i]=$mac
  fi
done
gateway_profile="(version 1) (allow default) (deny file-write*) (deny network*)
(deny file-read* (subpath \"/Users\")) (deny file-read* (subpath \"/private/var/root\")) (deny file-read* (subpath \"/Volumes\"))
(allow network-bind) (allow network-inbound)"
if [ "$route_mode" = direct ]; then
  gateway_profile="$gateway_profile (allow network-outbound)"
  gateway_arg=$source
else
  gateway_profile="$gateway_profile (allow network-outbound (remote ip \"localhost:*\"))"
  gateway_arg=$proxy_port
fi
(
  export NAPTD_CONTROLLER_PID="$$" NAPTD_RELAY_TOKEN="$relay_secret" NAPTD_PROXY_AUTH_FILE="$dir/auth"
  export NAPTD_DNS_SERVER="$dns_server" NAPTD_DNS_SECONDARY="$dns_secondary"
  if [ "$lan_port" != 0 ]; then
    export NAPTD_LAN_PORT="$lan_port" NAPTD_LAN_INTERFACE="$source" NAPTD_LAN_AUTH_FILE="$dir/lan-auth"
    # The strict upstream-mode sandbox only permits localhost egress, so LAN
    # UDP replies cannot be delivered; reject association explicitly.
    if [ "$route_mode" != direct ]; then export NAPTD_LAN_UDP_DISABLED=1; fi
  fi
  exec /usr/bin/sandbox-exec -p "$gateway_profile" "$dir/socks_gateway" "$route_mode" "$gateway_arg"
) >"$dir/gateway.log" 2>&1 & gateway=$!
i=0; while [ "$i" -lt 45 ] && ! /usr/bin/grep -q '^gateway_ready:' "$dir/gateway.log"; do
  /bin/kill -0 "$gateway" 2>/dev/null || break
  /bin/sleep .2; i=$((i+1))
done
if ! /usr/bin/grep -q '^gateway_ready:' "$dir/gateway.log"; then
  if [ "$lan_port" != 0 ] && /usr/bin/grep -q '^lan_' "$dir/gateway.log"; then
    fail "局域网代理无法启动，请更换端口或检查 Wi-Fi 地址（$(/usr/bin/grep -m1 '^lan_' "$dir/gateway.log")）。"
  fi
  if [ "$route_mode" = socks5 ]; then fail '代理未启动、端口不可用或 SOCKS5 认证失败。'; fi
  fail 'Wi-Fi 直连组件无法启动。'
fi
relay_tcp=$(/usr/bin/awk -F: '/^gateway_ready:/{print $2; exit}' "$dir/gateway.log")
relay_udp=$(/usr/bin/awk -F: '/^gateway_ready:/{print $3; exit}' "$dir/gateway.log")
[[ "$relay_tcp" =~ ^[0-9]{1,5}$ && "$relay_udp" =~ ^[0-9]{1,5}$ ]] || fail '连接组件端口无效。'
if [ "$lan_port" != 0 ]; then
  reported_lan=$(/usr/bin/awk -F: '/^gateway_ready:/{print $4; exit}' "$dir/gateway.log")
  [ "$reported_lan" = "$lan_port" ] || fail '局域网代理端口未能启动，请更换端口或检查 Wi-Fi。'
  lan_ready=1; lan_state=listening
fi
/bin/rm -f "$dir/auth" "$dir/lan-auth"

# Record both the generated name and its hardware address before using a
# temporary interface; the supervisor can safely retry cleanup after a crash.
record_interface() {
  local name=$1 kind=$2 info mac index
  case "$kind:$name" in feth:feth[0-9]*|bridge:bridge[0-9]*) ;; *) return 1;; esac
  [[ "$name" =~ ^(feth|bridge)[0-9]+$ ]] || return 1
  info=$(/sbin/ifconfig -v "$name" 2>/dev/null) || return 1
  mac=$(printf '%s\n' "$info" | /usr/bin/awk '/^[[:space:]]*ether /{print $2; exit}')
  index=$(printf '%s\n' "$info" | /usr/bin/awk 'NR==1 { for(i=1;i<NF;i++) if($i=="index") {print $(i+1); exit} }')
  [[ "$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || return 1
  [[ "$index" =~ ^[0-9]+$ ]] && [ "$index" -gt 0 ] || return 1
  if [ "$kind" = bridge ] && [ "$name" = "$bridge" ] && [ -n "$bridge_index" ]; then
    [ "$index" = "$bridge_index" ] || return 1
    [ "$mac" != "$bridge_mac" ] || return 0
  fi
  printf '%s %s %s %s\n' "$kind" "$name" "$mac" "$index" >> "$dir/interfaces" || return 1
  if [ "$kind" = bridge ] && [ "$name" = "$bridge" ]; then bridge_mac=$mac; bridge_index=$index; fi
  if [ "$kind" = feth ] && [ "$name" = "$endpoint" ]; then endpoint_mac=$mac; endpoint_index=$index; fi
  if [ "$kind" = feth ] && [ "$name" = "$peer" ]; then peer_mac=$mac; peer_index=$index; fi
}
# getifaddrs may redact hardware addresses, so obtain the host interface
# identities through ifconfig and atomically publish a root-only snapshot.
refresh_host_macs() {
  local info mac list old tmp="$dir/.host-macs.new" count=0
  info=$(/sbin/ifconfig -a 2>/dev/null) || return 1
  list=$(printf '%s\n' "$info" | /usr/bin/awk '$1 == "ether" {print tolower($2)}' | /usr/bin/sort -u) || return 1
  [ -n "$list" ] || return 1
  while IFS= read -r mac; do
    [[ "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
    [ "$mac" != '02:00:00:00:00:00' ] || return 1
    count=$((count+1))
  done <<< "$list"
  [ "$count" -gt 0 ] && [ "$count" -le 1024 ] || return 1
  if [ -f "$dir/host-macs" ] && [ ! -L "$dir/host-macs" ]; then
    old=$(/bin/cat "$dir/host-macs" 2>/dev/null) || return 1
    [ "$old" != "$list" ] || return 0
  fi
  [ ! -e "$tmp" ] && [ ! -L "$tmp" ] || return 1
  printf '%s\n' "$list" > "$tmp" || return 1
  /bin/chmod 600 "$tmp" && /bin/mv -f "$tmp" "$dir/host-macs" || return 1
}
if [ "$portcount" -gt 0 ]; then
endpoint=$(/sbin/ifconfig feth create) || fail '无法创建内部网络端口。'
[[ "$endpoint" =~ ^feth[0-9]+$ ]] && record_interface "$endpoint" feth || fail '无法记录内部网络端口。'
peer=$(/sbin/ifconfig feth create) || fail '无法创建内部网络端口。'
[[ "$peer" =~ ^feth[0-9]+$ ]] && record_interface "$peer" feth || fail '无法记录内部网络端口。'
bridge=$(/sbin/ifconfig bridge create) || fail '无法创建共享网桥。'
[[ "$bridge" =~ ^bridge[0-9]+$ ]] && record_interface "$bridge" bridge || fail '无法记录共享网桥。'
/sbin/ifconfig "$endpoint" peer "$peer" || fail '无法连接内部网络端口。'
/sbin/ifconfig "$endpoint" up && /sbin/ifconfig "$peer" up || fail '无法启用内部网络端口。'
/sbin/ifconfig "$bridge" addm "$endpoint" || fail '无法连接共享网桥。'
/sbin/ifconfig "$bridge" inet 172.30.79.2 netmask 255.255.255.0 up || fail '无法配置共享网桥。'
record_interface "$bridge" bridge || fail '无法记录共享网桥状态。'
refresh_host_macs || fail '无法检查本机网络端口地址。'
profile="(version 1) (allow default)
(deny file-write*) (deny network*)
(deny process-fork) (deny sysctl-write) (deny iokit-open)
(deny ipc-posix*) (deny ipc-sysv*)
(deny file-read* (subpath \"/Users\")) (deny file-read* (subpath \"/private/var/root\")) (deny file-read* (subpath \"/Volumes\"))
(allow file-read* file-write* (regex #\"^/dev/bpf[0-9]+$\"))
(allow file-write* (literal \"/dev/null\"))
(allow file-write* (subpath \"$lease_dir\"))
(allow network-bind) (allow network-inbound)
(allow network-outbound (remote ip \"localhost:$relay_tcp\"))
(allow network-outbound (remote ip \"localhost:$relay_udp\"))"
(
  export NAPTD_CONTROLLER_PID="$$" NAPTD_RELAY_TCP="$relay_tcp" NAPTD_RELAY_DNS="$relay_udp" NAPTD_RELAY_TOKEN="$relay_secret" NAPTD_RELAY_MODE="$route_mode"
  export NAPTD_DNS_SERVER="$dns_server" NAPTD_DNS_SECONDARY="$dns_secondary"
  export NAPTD_HOST_MAC_FILE="$dir/host-macs"
  exec /usr/bin/sandbox-exec -p "$profile" "$dir/runtime/standalone_bridge" --interface "$peer" --lease-dir "$lease_dir"
) >"$dir/bridge.log" 2>&1 & daemon=$!
i=0; while [ "$i" -lt 50 ] && ! /usr/bin/grep -q '^bridge_ready$' "$dir/bridge.log"; do
  /bin/kill -0 "$daemon" 2>/dev/null || break
  /bin/sleep .1; i=$((i+1))
done
/usr/bin/grep -q '^bridge_ready$' "$dir/bridge.log" || fail '转发程序无法启动。'

bridge_has_member() {
  /sbin/ifconfig "$bridge" 2>/dev/null | /usr/bin/grep -Eq "member: $1([[:space:]]|$)"
}

bridge_detach_safely() {
  if ! bridge_has_member "$1"; then return 0; fi
  /sbin/ifconfig "$bridge" deletem "$1" 2>/dev/null || ! bridge_has_member "$1"
}

interface_is_recorded_peer() {
  local name=$1 expected_mac=$2 expected_index=$3 expected_peer=$4 info mac index
  [[ "$name" =~ ^feth[0-9]+$ && "$expected_peer" =~ ^feth[0-9]+$ ]] || return 1
  [[ "$expected_index" =~ ^[0-9]+$ && "$expected_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || return 1
  info=$(/sbin/ifconfig -v "$name" 2>/dev/null) || return 1
  mac=$(printf '%s\n' "$info" | /usr/bin/awk '/^[[:space:]]*ether /{print $2; exit}')
  index=$(printf '%s\n' "$info" | /usr/bin/awk 'NR==1 { for(i=1;i<NF;i++) if($i=="index") {print $(i+1); exit} }')
  [ "$mac" = "$expected_mac" ] && [ "$index" = "$expected_index" ] || return 1
  printf '%s\n' "$info" | /usr/bin/grep -Eq "^[[:space:]]*peer:[[:space:]]*$expected_peer([[:space:]]|$)"
}

# Restore only our own bridge while both original feth endpoints and child
# processes are demonstrably intact. Never adopt a bridge made by another app.
recover_missing_bridge() {
  local listed item detail new_bridge parent routes
  [[ "$bridge" =~ ^bridge[0-9]+$ && "$bridge_index" =~ ^[0-9]+$ ]] || return 1
  /bin/kill -0 "$daemon" 2>/dev/null && /bin/kill -0 "$gateway" 2>/dev/null || return 1
  parent=$(/bin/ps -p "$daemon" -o ppid= 2>/dev/null | /usr/bin/tr -d '[:space:]')
  [ "$parent" = "$$" ] || return 1
  parent=$(/bin/ps -p "$gateway" -o ppid= 2>/dev/null | /usr/bin/tr -d '[:space:]')
  [ "$parent" = "$$" ] || return 1
  listed=$(/sbin/ifconfig -l 2>/dev/null) || return 1
  case " $listed " in *" $bridge "*) return 1;; esac
  interface_is_recorded_peer "$endpoint" "$endpoint_mac" "$endpoint_index" "$peer" || return 1
  interface_is_recorded_peer "$peer" "$peer_mac" "$peer_index" "$endpoint" || return 1
  for item in $listed; do
    case "$item" in bridge*)
      detail=$(/sbin/ifconfig "$item" 2>/dev/null) || return 1
      if printf '%s\n' "$detail" | /usr/bin/grep -Eq "member: ($endpoint|$peer)([[:space:]]|$)"; then return 1; fi;;
    esac
  done
  "$SUBNET_GUARD" >/dev/null 2>&1 || return 1
  routes=$(/usr/sbin/netstat -rn -f inet 2>/dev/null) || return 1
  if printf '%s\n' "$routes" | /usr/bin/awk '{print $1}' | /usr/bin/grep -Eq '^172\.30\.79(\.|/|$)'; then return 1; fi
  new_bridge=$(/sbin/ifconfig bridge create 2>/dev/null) || return 1
  [[ "$new_bridge" =~ ^bridge[0-9]+$ ]] || return 1
  case " $listed " in *" $new_bridge "*) return 1;; esac
  bridge=$new_bridge; bridge_index=''; bridge_mac=''; attached_list=''
  record_interface "$bridge" bridge || return 1
  /sbin/ifconfig "$bridge" addm "$endpoint" || return 1
  /sbin/ifconfig "$bridge" inet 172.30.79.2 netmask 255.255.255.0 up || return 1
  record_interface "$bridge" bridge || return 1
  bridge_has_member "$endpoint" || return 1
  refresh_host_macs || return 1
  state=waiting; message='正在恢复共享网桥'; write_state
}

remember_attached() {
  case " $attached_list " in *" $1 "*) ;; *) attached_list="$attached_list $1";; esac
}

reconcile_ports() {
  local snapshot='' scan_ok=1 ready=0 newmap='' newlist='' reason='' candidate previous initial info item
  local current_default has_external_ipv4 other_bridge observed_mac seen=' ' i missing nextstate nextmessage
  local oldstate=$state oldmessage=$message oldmap=$portmap oldlist=$portlist
  if [ "$needs_mobile" = 1 ]; then
    snapshot=$(/usr/bin/env NAPTD_DEVICE_SALT="$device_salt" "$dir/mobile_identity" 2>/dev/null) || scan_ok=0
  fi
  current_default=$(/sbin/route -n get default 2>/dev/null | /usr/bin/awk '/interface:/{print $2; exit}')
  for ((i=0; i<portcount; i++)); do
    initial=${original_ports[$i]}
    previous=${current_ports[$i]}
    candidate=''
    if [ "${port_kinds[$i]}" = mobile ]; then
      if [ "$scan_ok" = 1 ]; then
        candidate=$(resolve_mobile_iface "${port_ids[$i]}" "$snapshot" 2>/dev/null || true)
      fi
    else
      candidate=$initial
      info=$(/sbin/ifconfig "$candidate" 2>/dev/null || true)
      observed_mac=$(printf '%s\n' "$info" | /usr/bin/awk '/^[[:space:]]*ether /{print $2; exit}')
      if [ -z "$info" ] || [ "${port_macs[$i]}" = '-' ] || [ "$observed_mac" != "${port_macs[$i]}" ]; then candidate=''; fi
    fi
    if [ -z "$candidate" ]; then
      missing=${missing_counts[$i]}
      missing=$((missing+1)); missing_counts[$i]=$missing
      if [ "$scan_ok" = 1 ] && [ "$missing" -ge 2 ] && bridge_has_member "$previous"; then
        /sbin/ifconfig "$bridge" deletem "$previous" 2>/dev/null || true
      fi
      newmap="${newmap:+$newmap,}$initial:-"
      newlist="${newlist:+$newlist,}$previous"
      [ -n "$reason" ] || reason='等待已选择的设备重新连接'
      continue
    fi
    missing_counts[$i]=0
    if [ "$candidate" != "$previous" ] && bridge_has_member "$previous"; then
      /sbin/ifconfig "$bridge" deletem "$previous" 2>/dev/null || true
    fi
    current_ports[$i]=$candidate
    newmap="${newmap:+$newmap,}$initial:$candidate"
    newlist="${newlist:+$newlist,}$candidate"
    case "$seen" in *" $candidate "*) [ -n "$reason" ] || reason='检测到端口重复，正在等待'; continue;; esac
    seen="$seen$candidate "
    info=$(/sbin/ifconfig "$candidate" 2>/dev/null || true)
    if [ -z "$info" ] || { [ "${port_kinds[$i]}" = mobile ] && ! printf '%s\n' "$info" | /usr/bin/grep -q 'status: active'; }; then
      [ -n "$reason" ] || reason='等待已选择的设备重新连接'
      continue
    fi
    observed_mac=$(printf '%s\n' "$info" | /usr/bin/awk '/^[[:space:]]*ether /{print $2; exit}')
    if ! [[ "$observed_mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
      # An interface can disappear between identity discovery and ifconfig.
      # Detach any stale membership and wait for a complete fresh snapshot.
      bridge_detach_safely "$candidate" || fail "无法安全断开共享端口 $candidate。"
      [ -n "$reason" ] || reason='等待已选择的设备重新连接'
      continue
    fi
    if ! /usr/bin/grep -Fixq "$observed_mac" "$dir/host-macs"; then
      if ! refresh_host_macs || ! /usr/bin/grep -Fixq "$observed_mac" "$dir/host-macs"; then
        bridge_detach_safely "$candidate" || fail "无法安全断开共享端口 $candidate。"
        [ -n "$reason" ] || reason='等待共享端口地址稳定'
        continue
      fi
    fi
    has_external_ipv4=0; other_bridge=0
    if printf '%s\n' "$info" | /usr/bin/grep -E '^[[:space:]]*inet ' | /usr/bin/grep -vq 'inet 169\.254\.'; then has_external_ipv4=1; fi
    for item in $(/sbin/ifconfig -l); do
      case "$item" in bridge*)
        if [ "$item" != "$bridge" ] && /sbin/ifconfig "$item" 2>/dev/null | /usr/bin/grep -Eq "member: ${candidate}([[:space:]]|$)"; then other_bridge=1; break; fi;;
      esac
    done
    if ! interface_attach_allowed "$candidate" "$source" "$current_default" "$has_external_ipv4" "$other_bridge"; then
      if bridge_has_member "$candidate"; then /sbin/ifconfig "$bridge" deletem "$candidate" 2>/dev/null || true; fi
      [ -n "$reason" ] || reason="共享端口 $candidate 正被其他网络使用"
      continue
    fi
    if ! bridge_has_member "$candidate"; then
      if ! refresh_host_macs || ! /usr/bin/grep -Fixq "$observed_mac" "$dir/host-macs"; then
        [ -n "$reason" ] || reason='等待共享端口地址稳定'
        continue
      fi
      if /sbin/ifconfig "$bridge" addm "$candidate" up 2>/dev/null && bridge_has_member "$candidate"; then
        record_interface "$bridge" bridge || fail '无法记录共享网桥状态。'
        if ! refresh_host_macs || ! /usr/bin/grep -Fixq "$observed_mac" "$dir/host-macs"; then
          # Do not leave a port bridged when its host identity cannot be checked.
          bridge_detach_safely "$candidate" || fail "无法安全断开共享端口 $candidate。"
          record_interface "$bridge" bridge || fail '无法记录共享网桥状态。'
          [ -n "$reason" ] || reason='等待共享端口地址稳定'
          continue
        fi
        remember_attached "$candidate"
      else
        [ -n "$reason" ] || reason="正在等待共享端口 $candidate 接入"
        continue
      fi
    else
      remember_attached "$candidate"
    fi
    ready=$((ready+1))
  done
  portmap=$newmap; portlist=$newlist
  if [ "$ready" = "$portcount" ]; then
    nextstate=running; nextmessage='共享端口已接入'
  else
    nextstate=waiting; nextmessage="${reason:-等待共享端口重新连接}（${ready}/${portcount}）"
  fi
  state=$nextstate; message=$nextmessage
  if [ "$state" != "$oldstate" ] || [ "$message" != "$oldmessage" ] || [ "$portmap" != "$oldmap" ] || [ "$portlist" != "$oldlist" ]; then write_state; fi
}

state=waiting; phase=running; message='正在接入所选端口'; write_state
bridge_recovery_count=0; bridge_recovery_window=0
while :; do
  [ -f "$dir/control" ] && [ ! -L "$dir/control" ] || fail '控制文件不可用。'
  command=$(/bin/cat "$dir/control" 2>/dev/null || true)
  [ "$command" != STOP ] || break
  kill -0 "$gui_pid" 2>/dev/null || break
  /bin/kill -0 "$daemon" 2>/dev/null || fail '转发程序已退出。'
  /bin/kill -0 "$gateway" 2>/dev/null || fail '连接组件已退出，共享已停止。'
  if ! /sbin/ifconfig "$bridge" >/dev/null 2>&1; then
    state=waiting; message='正在检查共享网桥'; write_state
    /bin/sleep 1
    if ! /sbin/ifconfig "$bridge" >/dev/null 2>&1; then
      now=$(/bin/date +%s)
      [[ "$now" =~ ^[0-9]+$ ]] || fail '无法检查共享网桥。'
      if (( now < bridge_recovery_window || now - bridge_recovery_window >= 60 )); then
        bridge_recovery_count=0; bridge_recovery_window=$now
      fi
      bridge_recovery_count=$((bridge_recovery_count+1))
      [ "$bridge_recovery_count" -le 3 ] || fail '共享网桥反复消失，请检查系统网络设置。'
      recover_missing_bridge || fail '共享网桥已消失，无法安全恢复。'
    fi
  fi
  reconcile_ports
  found_clients=$(/usr/sbin/arp -an -i "$bridge" 2>/dev/null | /usr/bin/awk -F '[()]' '{print $2}' | /usr/bin/grep -E '^172\.30\.79\.[0-9]{1,3}$' | /usr/bin/grep -Ev '^172\.30\.79\.(1|2)$' | /usr/bin/sort -u | /usr/bin/paste -sd ',' - || true)
  if [ "$found_clients" != "$clients" ]; then clients=$found_clients; write_state; fi
  /bin/sleep 2
done
else
state=running; phase=running; message='局域网代理已就绪'; write_state
while :; do
  [ -f "$dir/control" ] && [ ! -L "$dir/control" ] || fail '控制文件不可用。'
  command=$(/bin/cat "$dir/control" 2>/dev/null || true)
  [ "$command" != STOP ] || break
  kill -0 "$gui_pid" 2>/dev/null || break
  /bin/kill -0 "$gateway" 2>/dev/null || fail '连接组件已退出，共享已停止。'
  /bin/sleep 2
done
fi
