#!/bin/bash
# Selected interfaces are used as downstream ports.
set -u
umask 077
SCRIPT_DIR=$(/usr/bin/dirname "$0")
CONTENTS=$(/usr/bin/dirname "$SCRIPT_DIR")
TEMPLATE="$SCRIPT_DIR/network.desktop.xml"
DAEMON="$CONTENTS/MacOS/prl_naptd"
DISPATCHER="$CONTENTS/MacOS/mock_dispatcher"
SHIM="$SCRIPT_DIR/private_runtime.dylib"
GATEWAY="$CONTENTS/MacOS/socks_gateway"
IDENTITY="$CONTENTS/MacOS/mobile_identity"
SUPERVISOR="$CONTENTS/MacOS/session_supervisor"
SUBNET_GUARD="$CONTENTS/MacOS/subnet_guard"
LEASE_STORE="$CONTENTS/MacOS/lease_store"
RECONNECT_HELPERS="$SCRIPT_DIR/reconnect_helpers.sh"
FRAMEWORKS="$CONTENTS/Frameworks"

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

if [ "$mode" = launch ]; then
  [ "$#" -ge 8 ] && [ "$#" -le 15 ] || die '需要用户编号、应用进程、Wi-Fi、连接模式、DNS 和至少一个共享端口。'
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
  for path in "$TEMPLATE" "$DAEMON" "$DISPATCHER" "$SHIM" "$GATEWAY" "$IDENTITY" "$SUPERVISOR" "$SUBNET_GUARD" "$LEASE_STORE" "$FRAMEWORKS"; do
    [ -e "$path" ] || die '应用组件缺失。'
  done
  dir=$(/usr/bin/mktemp -d /private/tmp/networksharer.XXXXXXXX) || exit 1
  /bin/chmod 711 "$dir" || exit 1
  printf 'NetworkSharerSession/1\n' > "$dir/session.marker" || exit 1
  printf '%s\n' "$gui_pid" > "$dir/session.owner" || exit 1
  printf 'WAIT\n' > "$dir/control" || exit 1
  /usr/sbin/chown "$owner" "$dir/control" || exit 1
  /bin/chmod 600 "$dir/control" || exit 1
  printf '\000\000' > "$dir/auth" || exit 1
  /usr/sbin/chown "$owner" "$dir/auth" || exit 1
  /bin/chmod 600 "$dir/auth" || exit 1
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

[ "$mode" = _run ] && [ "$#" -ge 8 ] || die '未知操作。'
dir=$1; gui_pid=$2; source=$3; route_mode=$4; proxy_port=$5; dns_server=$6; dns_secondary=$7; shift 7
case "$dir" in /private/tmp/networksharer.????????) ;; *) die '运行目录无效。';; esac
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
daemon=''; stub=''; gateway=''; bridge=''; attached_list=''; clients=''; state='starting'; phase='awaiting_config'; message='正在准备连接配置'; net_uuid=''
write_state() {
  printf 'state=%s\nphase=%s\nmessage=%s\nsource=%s\ninterfaces=%s\nportmap=%s\nmode=%s\ndns=%s\ndns_secondary=%s\nbridge=%s\nclients=%s\nnetwork_uuid=%s\ndaemon_pid=%s\ngateway_pid=%s\n' "$state" "$phase" "$message" "$source" "$portlist" "$portmap" "$route_mode" "$dns_server" "$dns_secondary" "$bridge" "$clients" "$net_uuid" "$daemon" "$gateway" > "$dir/state.new"
  /bin/chmod 644 "$dir/state.new"
  /bin/mv -f "$dir/state.new" "$dir/state"
}
cleanup() {
  if [ -n "$bridge" ]; then
    for member in $attached_list; do /sbin/ifconfig "$bridge" deletem "$member" 2>/dev/null || true; done
  fi
  if [ -n "$daemon" ]; then /bin/kill -KILL "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; fi
  if [ -n "$stub" ]; then /bin/kill -KILL "$stub" 2>/dev/null || true; wait "$stub" 2>/dev/null || true; fi
  if [ -n "$gateway" ]; then /bin/kill -KILL "$gateway" 2>/dev/null || true; wait "$gateway" 2>/dev/null || true; fi
  /bin/rm -f "$dir/auth" 2>/dev/null || true
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
"$SUBNET_GUARD" >/dev/null 2>&1 || fail '共享网段与现有网络接口冲突，或无法检查网络。'
if /usr/sbin/netstat -rn -f inet | /usr/bin/awk '{print $1}' | /usr/bin/grep -Eq '^172\.30\.77(\.|/|$)'; then fail '共享网段已有路由。'; fi
net_uuid=$(/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]')
namepart=${net_uuid//-/}
relay_secret=$(/usr/bin/uuidgen | /usr/bin/tr -d '-' | /usr/bin/tr '[:upper:]' '[:lower:]')
[[ "$relay_secret" =~ ^[0-9a-f]{32}$ ]] || fail '无法生成连接组件密钥。'
dispatcher_name="com.naptdlab.dispatcher.$namepart"
service_name="com.naptdlab.engine.$namepart"
/bin/mkdir -p "$dir/Contents/MacOS" || fail '无法创建运行目录。'
/usr/bin/ditto "$FRAMEWORKS" "$dir/Contents/Frameworks" || fail '无法复制运行组件。'
/bin/cp "$DAEMON" "$dir/Contents/MacOS/prl_naptd" || fail '无法复制转发程序。'
/bin/cp "$DISPATCHER" "$dir/mock_dispatcher" || fail '无法复制调度组件。'
/bin/cp "$SHIM" "$dir/private_runtime.dylib" || fail '无法复制隔离组件。'
/bin/cp "$GATEWAY" "$dir/socks_gateway" || fail '无法复制连接组件。'
/bin/cp "$IDENTITY" "$dir/mobile_identity" || fail '无法复制设备识别组件。'
/usr/bin/sed "s/6ef84f03-b82f-4177-a954-5f788078a859/$net_uuid/g" "$TEMPLATE" > "$dir/network.desktop.xml" || fail '无法准备网络配置。'
lease_path=$("$LEASE_STORE") || fail '无法安全准备 DHCP 租约目录。'
[ "$lease_path" = '/private/var/db/com.local.networksharer/dhcp-leases.ini' ] || fail 'DHCP 租约路径无效。'
qt_config="$dir/qt-config"
/bin/mkdir -m 700 "$qt_config" || fail '无法准备隔离配置目录。'
/bin/ln -s "$dir/network.desktop.xml" "$qt_config/network.desktop.xml" || fail '无法准备隔离配置。'
/bin/ln -s "$lease_path" "$qt_config/parallels_dhcp_leases" || fail '无法准备 DHCP 租约。'
/bin/ln -s "$lease_path" "$qt_config/.parallels_dhcp_leases" || fail '无法准备 DHCP 租约。'
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
  exec /usr/bin/sandbox-exec -p "$gateway_profile" "$dir/socks_gateway" "$route_mode" "$gateway_arg"
) >"$dir/gateway.log" 2>&1 & gateway=$!
i=0; while [ "$i" -lt 45 ] && ! /usr/bin/grep -q '^gateway_ready:' "$dir/gateway.log"; do
  /bin/kill -0 "$gateway" 2>/dev/null || break
  /bin/sleep .2; i=$((i+1))
done
if ! /usr/bin/grep -q '^gateway_ready:' "$dir/gateway.log"; then
  if [ "$route_mode" = socks5 ]; then fail '代理未启动、端口不可用或 SOCKS5 认证失败。'; fi
  fail 'Wi-Fi 直连组件无法启动。'
fi
relay_tcp=$(/usr/bin/awk -F: '/^gateway_ready:/{print $2; exit}' "$dir/gateway.log")
relay_udp=$(/usr/bin/awk -F: '/^gateway_ready:/{print $3; exit}' "$dir/gateway.log")
[[ "$relay_tcp" =~ ^[0-9]{1,5}$ && "$relay_udp" =~ ^[0-9]{1,5}$ ]] || fail '连接组件端口无效。'
/bin/rm -f "$dir/auth"
profile="(version 1) (allow default)
(deny file-write*) (deny network*) (deny mach-lookup) (deny mach-register)
(deny signal) (deny process-fork) (deny sysctl-write) (deny iokit-open)
(deny ipc-posix*) (deny ipc-sysv*)
(deny file-read* (subpath \"/Users\")) (deny file-read* (subpath \"/private/var/root\")) (deny file-read* (subpath \"/Volumes\"))
(deny file-read* (subpath \"/Library/Preferences/Parallels\"))
(deny file-read* (literal \"/Library/Logs/parallels.log\"))
(allow file-write* (literal \"/dev/null\"))
(allow file-write* (subpath \"$qt_config\"))
(allow file-write* (subpath \"/private/var/db/com.local.networksharer\"))
(allow mach-lookup (global-name \"$dispatcher_name\"))
(allow mach-register (global-name \"$service_name\"))
(allow mach-lookup (global-name \"com.apple.SystemConfiguration.configd\"))
(allow mach-lookup (global-name \"com.apple.NetworkSharing\"))
(allow sysctl-read (sysctl-name-prefix \"net.routetable.\"))
(allow network-bind) (allow network-inbound)
(allow network-outbound (remote ip \"localhost:$relay_tcp\"))
(allow network-outbound (remote ip \"localhost:$relay_udp\"))"
stub_profile="(version 1) (allow default) (deny file-write*) (deny network*)
(deny mach-register) (allow mach-register (global-name \"$dispatcher_name\"))
(deny signal) (deny process-fork) (deny sysctl-write) (deny iokit-open) (deny ipc-posix*) (deny ipc-sysv*)
(deny file-read* (subpath \"/Users\")) (deny file-read* (subpath \"/private/var/root\")) (deny file-read* (subpath \"/Volumes\"))"
/usr/bin/sandbox-exec -p "$stub_profile" /usr/bin/env NAPTD_CONTROLLER_PID="$$" NAPTD_DISPATCHER_PORT="$dispatcher_name" "$dir/mock_dispatcher" >"$dir/dispatcher.log" 2>&1 & stub=$!
i=0; while [ "$i" -lt 30 ] && ! /usr/bin/grep -q dispatcher_ready "$dir/dispatcher.log"; do /bin/sleep .2; i=$((i+1)); done
/usr/bin/grep -q dispatcher_ready "$dir/dispatcher.log" || fail '调度组件无法启动。'
(
  export NAPTD_CONTROLLER_PID="$$" NAPTD_CONFIG_DIR="$dir" PARALLELS_CONFIG_DIR="$qt_config" NAPTD_DISPATCHER_PORT="$dispatcher_name" NAPTD_SERVICE_PORT="$service_name"
  export NAPTD_RELAY_TCP="$relay_tcp" NAPTD_RELAY_DNS="$relay_udp" NAPTD_RELAY_TOKEN="$relay_secret" NAPTD_RELAY_MODE="$route_mode"
  exec /usr/bin/sandbox-exec -p "$profile" /usr/bin/env DYLD_INSERT_LIBRARIES="$dir/private_runtime.dylib" "$dir/Contents/MacOS/prl_naptd" start debug
) >/dev/null 2>&1 & daemon=$!
/bin/sleep 2
/bin/kill -0 "$daemon" 2>/dev/null || fail '转发程序无法启动。'
count=0
for candidate in $(/sbin/ifconfig -l); do
  case "$candidate" in bridge*) case " $before " in *" $candidate "*) ;; *) bridge="$candidate"; count=$((count+1));; esac;; esac
done
[ "$count" = 1 ] || fail '无法唯一确定新建的网络桥接。'

bridge_has_member() {
  /sbin/ifconfig "$bridge" 2>/dev/null | /usr/bin/grep -Eq "member: $1([[:space:]]|$)"
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
      if /sbin/ifconfig "$bridge" addm "$candidate" up 2>/dev/null && bridge_has_member "$candidate"; then
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
while :; do
  [ -f "$dir/control" ] && [ ! -L "$dir/control" ] || fail '控制文件不可用。'
  command=$(/bin/cat "$dir/control" 2>/dev/null || true)
  [ "$command" != STOP ] || break
  kill -0 "$gui_pid" 2>/dev/null || break
  /bin/kill -0 "$daemon" 2>/dev/null || fail '转发程序已退出。'
  /bin/kill -0 "$stub" 2>/dev/null || fail '调度组件已退出。'
  /bin/kill -0 "$gateway" 2>/dev/null || fail '连接组件已退出，共享已停止。'
  /sbin/ifconfig "$bridge" >/dev/null 2>&1 || fail '共享网桥已消失。'
  reconcile_ports
  found_clients=$(/usr/sbin/arp -an -i "$bridge" 2>/dev/null | /usr/bin/awk -F '[()]' '{print $2}' | /usr/bin/grep -E '^172\.30\.77\.[0-9]{1,3}$' | /usr/bin/grep -Ev '^172\.30\.77\.(1|2)$' | /usr/bin/sort -u | /usr/bin/paste -sd ',' - || true)
  if [ "$found_clients" != "$clients" ]; then clients=$found_clients; write_state; fi
  /bin/sleep 2
done
