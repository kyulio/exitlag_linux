#!/usr/bin/env bash
# Rootless kernel TPROXY + NFSDK IPC bridge end-to-end test inside `unshare -Urn`.
# Spawns a separate origin server netns behind a veth link (so 203.0.113.10 is a
# real routed non-local IP) and exercises real `shim/build/exitlag-nf-redir`:
#   1) TCP passthrough (ALLOW_DIRECT) + verified process name resolution
#   2) TCP redirect (REDIRECT -> mock ExitLag local proxy verifying peer_port == local_port!)
#   3) UDP passthrough (MSG_UDP_POST_SEND + MSG_UDP_DISABLE_FILTER) with spoofed peer reply
#   4) UDP proxied (MSG_UDP_SEND -> MSG_UDP_POST_RECV) with spoofed peer reply
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REDIR="$ROOT/shim/build/exitlag-nf-redir"

if [[ ! -x "$REDIR" ]]; then
  echo "missing $REDIR — run shim/linux/build.sh first" >&2
  exit 1
fi

exec unshare -Urn bash -s "$REDIR" <<'INNER'
set -euo pipefail
REDIR="$1"
TMP="$(mktemp -d)"
ORIG_NS_PID=""
REDIR_PID=""

cleanup() {
  rc=$?
  [[ -n "$REDIR_PID" ]] && kill "$REDIR_PID" 2>/dev/null || true
  [[ -n "$ORIG_NS_PID" ]] && kill "$ORIG_NS_PID" 2>/dev/null || true
  if [[ "$rc" -ne 0 ]]; then
    echo "=== REDIR LOG ==="
    cat "$TMP/redir.log" 2>/dev/null || true
    echo "=== ORIG LOG ==="
    cat "$TMP/orig.log" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

ip link set lo up
ip link add veth-host type veth peer name veth-orig
ip addr add 198.51.100.1/30 dev veth-host
ip link set veth-host up

# Spawn origin network namespace holding 203.0.113.10 on veth-orig
unshare -n python3 - <<'PY' "$TMP/orig.pid" "$TMP/orig.ready" > "$TMP/orig.log" 2>&1 &
import os, socket, subprocess, sys, threading, time
with open(sys.argv[1], 'w') as f:
    f.write(str(os.getpid()))
# Wait until veth-orig appears in THIS netns (via netlink, not host /sys)
while subprocess.run(['ip', 'link', 'show', 'dev', 'veth-orig'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
    time.sleep(0.02)
rc = os.system('ip link set lo up && ip link set veth-orig up && ip addr add 203.0.113.10/32 dev lo && ip addr add 198.51.100.2/30 dev veth-orig && ip route add default via 198.51.100.1')
assert rc == 0, f'netns ip config failed: {rc}'

origin_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
origin_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
origin_tcp.bind(('203.0.113.10', 8080))
origin_tcp.listen(16)

def serve_tcp():
    while True:
        c, _ = origin_tcp.accept()
        def _h(conn):
            with conn:
                data = conn.recv(4096)
                conn.sendall(b'DIRECT_TCP_OK:' + data)
        threading.Thread(target=_h, args=(c,), daemon=True).start()

threading.Thread(target=serve_tcp, daemon=True).start()

origin_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
origin_udp.bind(('203.0.113.10', 5353))
with open(sys.argv[2], 'w') as f:
    f.write('ready\n')
while True:
    pkt, addr = origin_udp.recvfrom(4096)
    origin_udp.sendto(b'DIRECT_UDP_OK:' + pkt, addr)
PY
ORIG_NS_PID=$!

for _ in $(seq 1 50); do
  [[ -s "$TMP/orig.pid" ]] && break
  sleep 0.05
done
ip link set veth-orig netns "$(cat "$TMP/orig.pid")"
for _ in $(seq 1 50); do
  [[ -f "$TMP/orig.ready" ]] && break
  sleep 0.05
done
ip route add 203.0.113.10/32 via 198.51.100.2 dev veth-host

ip -4 rule add fwmark 0x1 lookup 100
ip -4 route replace local 0.0.0.0/0 dev lo table 100

nft -f - <<'NFT'
table inet test_nf_tproxy {
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark 0xff return
        ip daddr 203.0.113.10 meta l4proto { tcp, udp } meta mark set 0x1 accept
    }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta mark 0xff return
        meta mark 0x1 ip daddr 203.0.113.10 meta l4proto tcp tproxy ip to 127.0.0.1:12345
        meta mark 0x1 ip daddr 203.0.113.10 meta l4proto udp tproxy ip to 127.0.0.1:12345
    }
}
NFT

"$REDIR" --listen-tcp 127.0.0.1:12345 --listen-udp 127.0.0.1:12345 --ipc 127.0.0.1:19851 --verbose > "$TMP/redir.log" 2>&1 &
REDIR_PID=$!
for _ in $(seq 1 40); do
  grep -q "NF REDIR READY" "$TMP/redir.log" 2>/dev/null && break
  sleep 0.1
done

python3 - <<'PY'
import socket, struct, threading, time

MSG_HELLO = 1
MSG_TCP_CONNECT_REQ = 2
MSG_TCP_CONNECT_RESP = 3
MSG_TCP_CLOSED = 4
MSG_UDP_CREATED = 5
MSG_UDP_SEND = 6
MSG_UDP_CLOSED = 7
MSG_UDP_POST_SEND = 8
MSG_UDP_POST_RECV = 9
MSG_UDP_DISABLE_FILTER = 10

TCP_ALLOW_DIRECT = 0
TCP_REDIRECT = 2

HDR_FMT = '<BBHI'
HELLO_FMT = '<II'
TCP_REQ_FMT = '<QIBxH16sHH16s'
TCP_RESP_FMT = '<QBBH16s'
UDP_CR_FMT = '<QIBxH16sHH'
UDP_PKT_FMT = '<QBBH16s'

def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        c = conn.recv(n - len(buf))
        if not c:
            return None
        buf.extend(c)
    return bytes(buf)

def send_frame(sock, mtype, payload):
    sock.sendall(struct.pack(HDR_FMT, mtype, 0, 0, len(payload)) + payload)

expected_proxy_ports = {}
proxy_lock = threading.Lock()
exitlag_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
exitlag_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
exitlag_proxy.bind(('127.0.0.1', 0))
exitlag_proxy_port = exitlag_proxy.getsockname()[1]
exitlag_proxy.listen(16)

def serve_exitlag_proxy():
    while True:
        c, peer = exitlag_proxy.accept()
        def _h(conn, peer_addr):
            with conn:
                with proxy_lock:
                    dst = expected_proxy_ports.pop(peer_addr[1], None)
                assert dst is not None, f'missing mapping for peer port {peer_addr}'
                data = conn.recv(4096)
                conn.sendall(f'PROXY_TCP_OK:{dst[0]}:{dst[1]}:'.encode() + data)
        threading.Thread(target=_h, args=(c, peer), daemon=True).start()

threading.Thread(target=serve_exitlag_proxy, daemon=True).start()

ipc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ipc.connect(('127.0.0.1', 19851))
send_frame(ipc, MSG_HELLO, struct.pack(HELLO_FMT, 4242, 1))

tcp_mode = {'mode': 'direct'}
udp_mode = {'mode': 'proxy'}
seen_procs = []

def ipc_loop():
    while True:
        raw = recv_exact(ipc, 8)
        if not raw:
            break
        mtype, _, _, length = struct.unpack(HDR_FMT, raw)
        payload = recv_exact(ipc, length) if length else b''
        if payload is None:
            break
        if mtype == MSG_TCP_CONNECT_REQ:
            cid, lpid, af, plen, lip16, lport_be, rport_be, rip16 = struct.unpack(TCP_REQ_FMT, payload[:52])
            pname = payload[52:52+plen].decode('utf-8', errors='replace')
            seen_procs.append(('tcp', lpid, pname))
            rip = socket.inet_ntop(socket.AF_INET, rip16[:4])
            rport = socket.ntohs(rport_be)
            lport = socket.ntohs(lport_be)
            assert 'python' in pname.lower(), f'expected python proc_name, got {pname!r}'
            assert lpid > 0, f'expected non-zero linux_pid, got {lpid}'
            if tcp_mode['mode'] == 'direct':
                resp = struct.pack(TCP_RESP_FMT, cid, TCP_ALLOW_DIRECT, 4, rport_be, rip16)
            else:
                with proxy_lock:
                    expected_proxy_ports[lport] = (rip, rport)
                lo16 = socket.inet_pton(socket.AF_INET, '127.0.0.1') + b'\x00' * 12
                resp = struct.pack(TCP_RESP_FMT, cid, TCP_REDIRECT, 4, socket.htons(exitlag_proxy_port), lo16)
            send_frame(ipc, MSG_TCP_CONNECT_RESP, resp)
        elif mtype == MSG_UDP_CREATED:
            cid, lpid, af, plen, lip16, lport_be, _ = struct.unpack(UDP_CR_FMT, payload[:36])
            pname = payload[36:36+plen].decode('utf-8', errors='replace')
            seen_procs.append(('udp', lpid, pname))
            assert 'python' in pname.lower(), f'expected python proc_name, got {pname!r}'
            assert lpid > 0, f'expected non-zero linux_pid, got {lpid}'
        elif mtype == MSG_UDP_SEND:
            cid, af, _, rport_be, rip16 = struct.unpack(UDP_PKT_FMT, payload[:28])
            pkt = payload[28:]
            if udp_mode['mode'] == 'direct':
                send_frame(ipc, MSG_UDP_POST_SEND, payload[:28] + pkt)
                send_frame(ipc, MSG_UDP_DISABLE_FILTER, struct.pack('<Q', cid))
            else:
                rip = socket.inet_ntop(socket.AF_INET, rip16[:4])
                rport = socket.ntohs(rport_be)
                reply = f'PROXY_UDP_OK:{rip}:{rport}:'.encode() + pkt
                send_frame(ipc, MSG_UDP_POST_RECV, payload[:28] + reply)

threading.Thread(target=ipc_loop, daemon=True).start()
time.sleep(0.1)

# 1. TCP ALLOW_DIRECT
tcp_mode['mode'] = 'direct'
c1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c1.settimeout(5)
c1.connect(('203.0.113.10', 8080))
c1.sendall(b'hello1')
c1.shutdown(socket.SHUT_WR)
r1 = c1.recv(4096)
c1.close()
assert r1 == b'DIRECT_TCP_OK:hello1', r1
print('1) TCP ALLOW_DIRECT OK:', r1.decode())

# 2. TCP REDIRECT
tcp_mode['mode'] = 'redirect'
c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c2.settimeout(5)
c2.connect(('203.0.113.10', 8080))
c2.sendall(b'hello2')
c2.shutdown(socket.SHUT_WR)
r2 = c2.recv(4096)
c2.close()
assert r2 == b'PROXY_TCP_OK:203.0.113.10:8080:hello2', r2
print('2) TCP REDIRECT OK:', r2.decode())

# 3. UDP PROXY
udp_mode['mode'] = 'proxy'
u1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u1.settimeout(5)
u1.sendto(b'uhello1', ('203.0.113.10', 5353))
ud1, peer1 = u1.recvfrom(4096)
u1.close()
assert peer1 == ('203.0.113.10', 5353), peer1
assert ud1 == b'PROXY_UDP_OK:203.0.113.10:5353:uhello1', ud1
print('3) UDP PROXY OK:', ud1.decode(), 'peer=', peer1)

# 4. UDP PASSTHROUGH
udp_mode['mode'] = 'direct'
u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u2.settimeout(5)
u2.sendto(b'uhello2', ('203.0.113.10', 5353))
ud2, peer2 = u2.recvfrom(4096)
assert peer2 == ('203.0.113.10', 5353), peer2
assert ud2 == b'DIRECT_UDP_OK:uhello2', ud2
u2.sendto(b'uhello3', ('203.0.113.10', 5353))
ud3, peer3 = u2.recvfrom(4096)
u2.close()
assert peer3 == ('203.0.113.10', 5353), peer3
assert ud3 == b'DIRECT_UDP_OK:uhello3', ud3
print('4) UDP PASSTHROUGH OK:', ud2.decode(), '+', ud3.decode(), 'seen_procs=', seen_procs)

ipc.close()
PY
INNER
