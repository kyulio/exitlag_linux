#!/usr/bin/env bash
# Configure Linux nftables + policy routing TPROXY rules for exitlag-nf-redir.
# By default (--scope uid), all user non-local TCP/UDP traffic is inspected by
# ExitLag.exe via nfapi.dll while ExitLag.exe itself runs inside exitlagbypass.slice
# (and SO_MARK 0xff outbound sockets bypass TPROXY to prevent loops).
set -euo pipefail

DRY_RUN=0
ENABLE_IPV6=0
UID_NUM="${SUDO_UID:-$(id -u)}"
USER_NAME="${SUDO_USER:-$(id -un "$UID_NUM" 2>/dev/null || echo "")}"
SCOPE="uid"
BYPASS_CGROUP=""
TARGET_CGROUP=""
CGROUP_LEVEL=4
PORT_TCP=12345
PORT_UDP=12345
MARK_BYPASS=0xff
MARK_TPROXY=0x1
TABLE_ID=100

usage() {
  cat <<EOF
usage: $0 <up|down|status> [options]
  --dry-run                Print ip/nft commands without executing
  --uid <uid>              Target user UID (default $UID_NUM)
  --scope <uid|cgroup>     Redirect all UID traffic (default) or only target cgroup
  --bypass-cgroup <path>   Relative cgroupv2 path for ExitLag.exe bypass
  --target-cgroup <path>   Relative cgroupv2 path when --scope cgroup
  --level <n>              socket cgroupv2 level (default $CGROUP_LEVEL)
  --tcp-port <port>        exitlag-nf-redir TCP TPROXY port (default $PORT_TCP)
  --udp-port <port>        exitlag-nf-redir UDP TPROXY port (default $PORT_UDP)
  --ipv6                   Also configure ip6 rule/route/tproxy rules
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

ACTION="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --uid) UID_NUM="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    --bypass-cgroup) BYPASS_CGROUP="$2"; shift 2 ;;
    --target-cgroup) TARGET_CGROUP="$2"; shift 2 ;;
    --level) CGROUP_LEVEL="$2"; shift 2 ;;
    --tcp-port) PORT_TCP="$2"; shift 2 ;;
    --udp-port) PORT_UDP="$2"; shift 2 ;;
    --ipv6) ENABLE_IPV6=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ "$SCOPE" != "uid" && "$SCOPE" != "cgroup" ]]; then
  echo "invalid --scope '$SCOPE' (expected uid or cgroup)" >&2
  exit 2
fi

if [[ -z "$BYPASS_CGROUP" ]]; then
  BYPASS_CGROUP="user.slice/user-${UID_NUM}.slice/user@${UID_NUM}.service/exitlagbypass.slice"
fi
if [[ -z "$TARGET_CGROUP" ]]; then
  TARGET_CGROUP="user.slice/user-${UID_NUM}.slice/user@${UID_NUM}.service/exitlag.slice"
fi

ensure_cgroups_exist() {
  if [[ ! -d "/sys/fs/cgroup/$BYPASS_CGROUP" ]]; then
    echo "error: bypass cgroup /sys/fs/cgroup/$BYPASS_CGROUP does not exist." >&2
    echo "Launch ExitLag.exe under exitlagbypass.slice first (or pass --bypass-cgroup)." >&2
    exit 1
  fi
  if [[ "$SCOPE" == "cgroup" && ! -d "/sys/fs/cgroup/$TARGET_CGROUP" ]]; then
    echo "error: target cgroup /sys/fs/cgroup/$TARGET_CGROUP does not exist." >&2
    exit 1
  fi
}

generate_nft() {
  cat <<EOF
add table inet exitlag_nf_redir
flush table inet exitlag_nf_redir
table inet exitlag_nf_redir {
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark $MARK_BYPASS return
        socket cgroupv2 level $CGROUP_LEVEL "$BYPASS_CGROUP" return
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return
        ip6 daddr { ::/128, ::1/128, fe80::/10, fc00::/7, ff00::/8 } return
EOF
  if [[ "$SCOPE" == "uid" ]]; then
    cat <<EOF
        meta skuid $UID_NUM meta l4proto tcp meta mark set $MARK_TPROXY accept
        meta skuid $UID_NUM meta l4proto udp meta mark set $MARK_TPROXY accept
EOF
  else
    cat <<EOF
        socket cgroupv2 level $CGROUP_LEVEL "$TARGET_CGROUP" meta l4proto tcp meta mark set $MARK_TPROXY accept
        socket cgroupv2 level $CGROUP_LEVEL "$TARGET_CGROUP" meta l4proto udp meta mark set $MARK_TPROXY accept
EOF
  fi
  cat <<EOF
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta mark $MARK_BYPASS return
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return
        ip6 daddr { ::/128, ::1/128, fe80::/10, fc00::/7, ff00::/8 } return
        meta mark $MARK_TPROXY meta l4proto tcp tproxy ip to 127.0.0.1:$PORT_TCP
        meta mark $MARK_TPROXY meta l4proto udp tproxy ip to 127.0.0.1:$PORT_UDP
EOF
  if [[ "$ENABLE_IPV6" -eq 1 ]]; then
    cat <<EOF
        meta mark $MARK_TPROXY meta l4proto tcp tproxy ip6 to [::1]:$PORT_TCP
        meta mark $MARK_TPROXY meta l4proto udp tproxy ip6 to [::1]:$PORT_UDP
EOF
  fi
  cat <<EOF
    }
}
EOF
}

case "$ACTION" in
  up)
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "# ip -4 rule add fwmark $MARK_TPROXY lookup $TABLE_ID"
      echo "# ip -4 route replace local 0.0.0.0/0 dev lo table $TABLE_ID"
      if [[ "$ENABLE_IPV6" -eq 1 ]]; then
        echo "# ip -6 rule add fwmark $MARK_TPROXY lookup $TABLE_ID"
        echo "# ip -6 route replace local ::/0 dev lo table $TABLE_ID"
      fi
      generate_nft
      exit 0
    fi
    ensure_cgroups_exist
    ip -4 rule show | grep -q "fwmark 0x1 lookup $TABLE_ID" || ip -4 rule add fwmark "$MARK_TPROXY" lookup "$TABLE_ID"
    ip -4 route replace local 0.0.0.0/0 dev lo table "$TABLE_ID"
    if [[ "$ENABLE_IPV6" -eq 1 ]]; then
      ip -6 rule show | grep -q "fwmark 0x1 lookup $TABLE_ID" || ip -6 rule add fwmark "$MARK_TPROXY" lookup "$TABLE_ID"
      ip -6 route replace local ::/0 dev lo table "$TABLE_ID"
    fi
    generate_nft | nft -f -
    ;;
  down)
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "# nft delete table inet exitlag_nf_redir"
      echo "# ip -4 rule del fwmark $MARK_TPROXY lookup $TABLE_ID"
      echo "# ip -4 route flush table $TABLE_ID"
      exit 0
    fi
    nft delete table inet exitlag_nf_redir 2>/dev/null || true
    while ip -4 rule del fwmark "$MARK_TPROXY" lookup "$TABLE_ID" 2>/dev/null; do :; done
    ip -4 route flush table "$TABLE_ID" 2>/dev/null || true
    while ip -6 rule del fwmark "$MARK_TPROXY" lookup "$TABLE_ID" 2>/dev/null; do :; done
    ip -6 route flush table "$TABLE_ID" 2>/dev/null || true
    ;;
  status)
    echo "=== nft table inet exitlag_nf_redir ==="
    nft list table inet exitlag_nf_redir 2>&1 || true
    echo "=== ip rules ==="
    ip -4 rule show | grep -E "lookup $TABLE_ID|fwmark" || true
    ip -4 route show table "$TABLE_ID" 2>/dev/null || true
    ;;
  *)
    usage
    exit 2
    ;;
esac
