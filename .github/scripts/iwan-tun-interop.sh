#!/usr/bin/env bash
# iWAN third-party interop: the iwand client (built by reality-interop.sh
# download, a black box per docs/protocols/iwan.md §10.2) logs in to our
# inbound-iwan (anixcore) from a network namespace and uses the tunnel as
# its default route. Linux runners only; needs root (TUN, netns).
#
#   sudo ANIXCORE=<path> RUNNER_TEMP=<dir> iwan-tun-interop.sh run
#   sudo RUNNER_TEMP=<dir> iwan-tun-interop.sh logs
#
# Layout: namespace iwanc (veth 172.31.250.2) -> anixcore on the host
# (172.31.250.1:28700, pool 10.77.0.0/24). Targets live on a dummy link on
# the host: HTTP 192.0.2.80:18080, UDP echo 192.0.2.80:18081 and a fake
# resolver 192.0.2.53:53 (the inbound's dns_upstream) that answers every A
# query with 192.0.2.80. Checks per client: gateway ping, DNS through the
# gateway, a 2 MiB HTTP download by name, UDP echo with a reply larger than
# the session MTU, the user online and charged in the management API, and
# CLOSE on SIGTERM. A wrong password must be rejected.

set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
work="${RUNNER_TEMP}/iwan-tun-interop"
iwand="${RUNNER_TEMP}/reality-interop/bin/iwand"
ns=iwanc
server_ip=172.31.250.1
server_port=28700
api=127.0.0.1:28710
target_ip=192.0.2.80
resolver_ip=192.0.2.53

fail() {
  echo "::error::iwan interop: $*" >&2
  exit 1
}

# wait_for_log <file> <text> <seconds>
wait_for_log() {
  local file="$1" text="$2" seconds="$3"
  for _ in $(seq 1 $((seconds * 5))); do
    if grep -qF -- "${text}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

api_get() {
  curl -fsS --max-time 5 -H "Authorization: Bearer ${token}" "http://${api}$1"
}

write_helpers() {
  cat > "${work}/resolver.py" <<'PY'
# Answers every A query with the address in argv[2]; other types get no answer.
import socket, struct, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], 53))
answer_ip = socket.inet_aton(sys.argv[2])
while True:
    query, peer = sock.recvfrom(1500)
    if len(query) < 12:
        continue
    end = 12
    while end < len(query) and query[end] != 0:
        end += query[end] + 1
    question = query[12:end + 5]
    qtype = struct.unpack("!H", query[end + 1:end + 3])[0] if end + 3 <= len(query) else 0
    answers = 1 if qtype == 1 else 0
    reply = query[:2] + struct.pack("!HHHHH", 0x8180, 1, answers, 0, 0) + question
    if answers:
        reply += struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + answer_ip
    sock.sendto(reply, peer)
PY
  cat > "${work}/udp_echo.py" <<'PY'
# Echoes datagrams; "big:" gets a 3000-byte reply (larger than any session MTU).
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, peer = sock.recvfrom(65535)
    sock.sendto(bytes(i % 251 for i in range(3000)) if data == b"big:" else data, peer)
PY
  cat > "${work}/client.py" <<'PY'
# dns <server> <name>: prints the A answers. udp <ip> <port>: echo checks.
import socket, struct, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
if sys.argv[1] == "dns":
    name = b"".join(bytes([len(p)]) + p.encode() for p in sys.argv[3].split(".")) + b"\0"
    sock.sendto(struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1),
                (sys.argv[2], 53))
    reply = sock.recv(1500)
    count = struct.unpack("!H", reply[6:8])[0]
    offset = 12 + len(name) + 4
    for _ in range(count):
        rtype, _, _, length = struct.unpack("!HHIH", reply[offset + 2:offset + 12])
        if rtype == 1:
            print(socket.inet_ntoa(reply[offset + 12:offset + 16]))
        offset += 12 + length
else:
    target = (sys.argv[2], int(sys.argv[3]))
    for payload in (b"hello iwan", bytes(range(256)) * 4):
        sock.sendto(payload, target)
        assert sock.recv(65535) == payload, "udp echo mismatch"
    sock.sendto(b"big:", target)
    assert sock.recv(65535) == bytes(i % 251 for i in range(3000)), "large udp reply mismatch"
    print("udp ok")
PY
}

setup_network() {
  ip netns add "${ns}"
  ip link add iwan-h type veth peer name iwan-n
  ip link set iwan-n netns "${ns}"
  ip addr add "${server_ip}/30" dev iwan-h
  ip link set iwan-h up
  ip -n "${ns}" addr add 172.31.250.2/30 dev iwan-n
  ip -n "${ns}" link set iwan-n up
  ip -n "${ns}" link set lo up
  ip link add iwan-t type dummy
  ip addr add "${target_ip}/32" dev iwan-t
  ip addr add "${resolver_ip}/32" dev iwan-t
  ip link set iwan-t up
}

start_targets() {
  mkdir -p "${work}/www"
  head -c $((2 * 1024 * 1024)) /dev/urandom > "${work}/www/payload.bin"
  python3 -m http.server 18080 --bind "${target_ip}" --directory "${work}/www" \
    > "${work}/http.log" 2>&1 &
  python3 "${work}/udp_echo.py" "${target_ip}" 18081 > "${work}/udp-echo.log" 2>&1 &
  python3 "${work}/resolver.py" "${resolver_ip}" "${target_ip}" > "${work}/resolver.log" 2>&1 &
}

start_anixcore() {
  : "${ANIXCORE:?ANIXCORE is required}"
  token="$(openssl rand -hex 16)"
  plain_password="$(openssl rand -hex 8)"
  xor_password="$(openssl rand -hex 8)"
  cat > "${work}/anixcore.json" <<JSON
{
  "management": {"listen": "${api}", "token": "${token}"},
  "allow_private_targets": true,
  "inbounds": [
    {"tag": "iwan", "type": "iwan", "listen": "${server_ip}", "listen_port": ${server_port},
     "pool": "10.77.0.0/24", "mtu": 1400, "dns_upstream": "${resolver_ip}",
     "users": [
       {"name": "1001", "username": "plain", "password": "${plain_password}"},
       {"name": "1002", "username": "xor", "password": "${xor_password}", "address": "10.77.0.20"}
     ]}
  ]
}
JSON
  "${ANIXCORE}" check -c "${work}/anixcore.json"
  "${ANIXCORE}" run -c "${work}/anixcore.json" > "${work}/anixcore.log" 2>&1 &
  for _ in $(seq 1 100); do
    if api_get /v1/status > /dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  fail "anixcore did not start"
}

# client_config <name> <username> <password> <mtu> <encrypt>
client_config() {
  cat > "${work}/$1.conf" <<CONF
[iwan0]
server=${server_ip}
port=${server_port}
username=$2
password=$3
mtu=$4
encrypt=$5
CONF
}

# run_client <name> <user> <expected ip or prefix> <expected mtu> <encrypt Y|N>
run_client() {
  local name="$1" user="$2" ip="$3" mtu="$4" encrypt="$5"
  local log="${work}/iwand-${name}.log"
  echo "::group::iwand client ${name}"
  ip netns exec "${ns}" "${iwand}" -f "${work}/${name}.conf" -F > "${log}" 2>&1 &
  local pid=$!
  wait_for_log "${log}" "ESTABLISHED: ip=${ip}" 20 || fail "${name}: no ESTABLISHED ip=${ip}"
  grep -E "ESTABLISHED: ip=[0-9.]+ mtu=${mtu} encrypt=${encrypt} " "${log}" > /dev/null \
    || fail "${name}: expected mtu=${mtu} encrypt=${encrypt}"
  ip -n "${ns}" route add default dev iwan0

  ip netns exec "${ns}" ping -c 3 -W 2 10.77.0.1 || fail "${name}: gateway ping"
  local resolved
  resolved="$(ip netns exec "${ns}" python3 "${work}/client.py" dns 10.77.0.1 echo.iwan.test)"
  [[ "${resolved}" == "${target_ip}" ]] || fail "${name}: gateway DNS answered '${resolved}'"
  ip netns exec "${ns}" curl -fsS --max-time 60 \
    --resolve "echo.iwan.test:18080:${resolved}" \
    -o "${work}/download-${name}.bin" http://echo.iwan.test:18080/payload.bin \
    || fail "${name}: HTTP download"
  cmp "${work}/www/payload.bin" "${work}/download-${name}.bin" || fail "${name}: download differs"
  ip netns exec "${ns}" python3 "${work}/client.py" udp "${target_ip}" 18081 \
    || fail "${name}: UDP echo"

  api_get /v1/inbounds/iwan/online | python3 -c \
    "import json,sys; assert any(u['name']=='${user}' for u in json.load(sys.stdin)['online'])" \
    || fail "${name}: user ${user} is not online"
  api_get /v1/inbounds/iwan/traffic | python3 -c \
    "import json,sys; assert any(u['name']=='${user}' and u['down']>=2*1024*1024 for u in json.load(sys.stdin)['traffic'])" \
    || fail "${name}: user ${user} was not charged"

  kill -TERM "${pid}"
  wait_for_log "${log}" "sent CLOSE to server" 10 || fail "${name}: no CLOSE on SIGTERM"
  wait "${pid}" || true
  local gone=0
  for _ in $(seq 1 25); do
    if api_get /v1/inbounds/iwan/online | python3 -c \
      "import json,sys; sys.exit(any(u['name']=='${user}' for u in json.load(sys.stdin)['online']))"; then
      gone=1
      break
    fi
    sleep 0.2
  done
  [[ "${gone}" == 1 ]] || fail "${name}: session stayed online after CLOSE"
  echo "::endgroup::"
}

run() {
  [[ -x "${iwand}" ]] || fail "iwand is not built (run reality-interop.sh download first)"
  rm -rf "${work}"
  mkdir -p "${work}"
  write_helpers
  setup_network
  start_targets
  start_anixcore

  client_config plain plain "${plain_password}" 1300 0
  run_client plain 1001 10.77.0. 1300 N
  client_config xor xor "${xor_password}" 1600 1
  run_client xor 1002 10.77.0.20 1400 Y

  echo "::group::iwand client with a wrong password"
  client_config wrong plain "wrong-${plain_password:0:8}" 1400 0
  ip netns exec "${ns}" "${iwand}" -f "${work}/wrong.conf" -F > "${work}/iwand-wrong.log" 2>&1 &
  local pid=$!
  wait_for_log "${work}/iwand-wrong.log" "peer AUTH REJECTED" 20 || fail "wrong password was not rejected"
  kill -TERM "${pid}"
  wait "${pid}" || true
  echo "::endgroup::"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    echo "iWAN TUN interop: iwand client (plain, XOR, fixed address, wrong password) against inbound-iwan passed." \
      >> "${GITHUB_STEP_SUMMARY}"
  fi
  echo "iwan tun interop passed"
}

logs() {
  for log in anixcore iwand-plain iwand-xor iwand-wrong resolver udp-echo http; do
    if [[ -f "${work}/${log}.log" ]]; then
      echo "::group::${log}"
      tail -n 200 "${work}/${log}.log"
      echo "::endgroup::"
    fi
  done
}

case "${1:-}" in
  run) run ;;
  logs) logs ;;
  *) echo "usage: $0 run|logs" >&2; exit 2 ;;
esac
