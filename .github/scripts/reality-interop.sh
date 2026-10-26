#!/usr/bin/env bash
# REALITY (outbound-vless), VMess (outbound-vmess), Hysteria2
# (outbound-hysteria2), TUIC (outbound-tuic), Snell (outbound-snell) and
# Mieru (outbound-mieru) and iWAN (outbound-iwan) interop harness, plus the
# reverse direction: Xray-core,
# sing-box and Hysteria clients against our server inbounds
# (node-runtime client_interop). Linux runners only.
#
#   reality-interop.sh download   fetch Xray-core, sing-box and Hysteria
#                                 release binaries, official snell-server
#                                 builds and the official mita package, and
#                                 build iwand-server from a pinned commit
#                                 (needs Go; run in CI only, never
#                                 redistributed)
#   reality-interop.sh start      start targets and REALITY servers, write env
#   reality-interop.sh logs       print server logs (for failed runs)
#
# Versions come from XRAY_VERSION / SINGBOX_VERSION / HYSTERIA_VERSION (a
# release tag or "latest") and SNELL_VERSIONS (space-separated snell-server
# versions; a version that cannot be downloaded is skipped with a warning,
# except the v6 one) and MIERU_VERSION (an enfein/mieru release tag or
# "latest") and IWAND_COMMIT (Ricky-Hao/iwand commit, default 9f6a0e3). Keys,
# UUID, short id and passwords are generated per run.

set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
work="${RUNNER_TEMP}/reality-interop"
bin="${work}/bin"
mkdir -p "${bin}"

resolve_tag() {
  local repo="$1" requested="$2"
  if [[ -z "${requested}" || "${requested}" == latest ]]; then
    gh release view -R "${repo}" --json tagName -q .tagName
  else
    echo "${requested}"
  fi
}

download() {
  local xray_tag singbox_tag singbox_version hysteria_tag
  xray_tag="$(resolve_tag XTLS/Xray-core "${XRAY_VERSION:-latest}")"
  hysteria_tag="$(resolve_tag apernet/hysteria "${HYSTERIA_VERSION:-latest}")"
  singbox_tag="$(resolve_tag SagerNet/sing-box "${SINGBOX_VERSION:-latest}")"
  singbox_version="${singbox_tag#v}"

  gh release download "${xray_tag}" -R XTLS/Xray-core -p Xray-linux-64.zip -D "${work}" --clobber
  unzip -o -q "${work}/Xray-linux-64.zip" xray -d "${bin}"

  gh release download "${singbox_tag}" -R SagerNet/sing-box \
    -p "sing-box-${singbox_version}-linux-amd64.tar.gz" -D "${work}" --clobber
  tar -xzf "${work}/sing-box-${singbox_version}-linux-amd64.tar.gz" -C "${work}"
  cp "${work}/sing-box-${singbox_version}-linux-amd64/sing-box" "${bin}/sing-box"
  gh release download "${hysteria_tag}" -R apernet/hysteria -p hysteria-linux-amd64 \
    -O "${bin}/hysteria" --clobber
  chmod +x "${bin}/xray" "${bin}/sing-box" "${bin}/hysteria"

  "${bin}/xray" version | sed -n 1p
  "${bin}/sing-box" version | sed -n 1p
  "${bin}/hysteria" version | grep -i '^version' || true

  # Official snell-server builds, black-box interop only (docs/protocols/snell.md §10.1).
  local snell_version snell_rows=""
  for snell_version in ${SNELL_VERSIONS:-v3.0.1 v4.1.1 v5.0.1 v6.0.0rc2}; do
    local zip="${work}/snell-server-${snell_version}.zip"
    # No public v3.0.1 build is downloadable today (dl.nssurge.com and the
    # surge-networks GitHub releases both return 404), so v3 is skipped with
    # a warning until one is found.
    if curl -fsSL --retry 3 -o "${zip}" \
      "https://dl.nssurge.com/snell/snell-server-${snell_version}-linux-amd64.zip"; then
      mkdir -p "${work}/snell-${snell_version}"
      unzip -o -q "${zip}" snell-server -d "${work}/snell-${snell_version}"
      cp "${work}/snell-${snell_version}/snell-server" "${bin}/snell-server-${snell_version}"
      chmod +x "${bin}/snell-server-${snell_version}"
      echo "snell-server ${snell_version}: $("${bin}/snell-server-${snell_version}" -v 2>&1 | head -n 1 || true)"
      snell_rows+="| snell-server | ${snell_version} |"$'\n'
    elif [[ "${snell_version}" == v6* ]]; then
      echo "::error::snell-server ${snell_version} could not be downloaded"
      return 1
    else
      echo "::warning::snell-server ${snell_version} could not be downloaded; skipping it"
    fi
  done
  # Official mita server package, black-box interop only (docs/protocols/mieru.md §7).
  local mieru_tag
  mieru_tag="$(resolve_tag enfein/mieru "${MIERU_VERSION:-latest}")"
  gh release download "${mieru_tag}" -R enfein/mieru -p "mita_${mieru_tag#v}_amd64.deb" \
    -O "${work}/mita.deb" --clobber
  # iwand-server, a black box for outbound-iwan (docs/protocols/iwan.md §10.1).
  # Only built and run: its source is never read, linked or redistributed.
  local iwand_commit="${IWAND_COMMIT:-9f6a0e3}"
  rm -rf "${work}/iwand"
  git clone --quiet --filter=blob:none https://github.com/Ricky-Hao/iwand "${work}/iwand"
  git -C "${work}/iwand" checkout --quiet "${iwand_commit}"
  (cd "${work}/iwand" && CGO_ENABLED=0 go build -trimpath -o "${bin}/iwand-server" ./cmd/iwand-server)
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### REALITY interop servers"
      echo
      echo "| Server | Release |"
      echo "| --- | --- |"
      echo "| Xray-core | ${xray_tag} |"
      echo "| sing-box | ${singbox_tag} |"
      echo "| Hysteria | ${hysteria_tag} |"
      printf '%s' "${snell_rows}"
      echo "| mita | ${mieru_tag} |"
      echo "| iwand-server | ${iwand_commit} |"
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
}

wait_for_port() {
  local port="$1"
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "::error::port ${port} did not open"
  return 1
}

wait_for_udp_port() {
  local port="$1"
  for _ in $(seq 1 100); do
    if [[ -n "$(ss -Hlun "sport = :${port}")" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "::error::udp port ${port} did not open"
  return 1
}

start() {
  local www="${work}/www"
  mkdir -p "${www}"
  python3 -c "
import sys
data = bytes((i * 7 + 3) % 251 for i in range(1_000_000))
open(sys.argv[1], 'wb').write(data)
" "${www}/payload.bin"

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "${work}/target.key" -out "${work}/target.crt" -days 2 \
    -subj /CN=target.interop.test 2>/dev/null
  # Certificate for our own server inbounds, which Go clients verify by name.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "${work}/server.key" -out "${work}/server.crt" -days 2 \
    -subj /CN=server.interop.test -addext subjectAltName=DNS:server.interop.test 2>/dev/null

  # Inner TLS 1.3 target serving files, and the REALITY camouflage target.
  (cd "${www}" && exec openssl s_server -accept 127.0.0.1:18443 -tls1_3 -WWW -quiet \
    -cert "${work}/target.crt" -key "${work}/target.key") > "${work}/target-tls.log" 2>&1 &
  # The camouflage target must serve connections concurrently: REALITY servers
  # forward every unauthenticated client there, and a single-threaded
  # `openssl s_server` stalls behind a forwarded connection that stays open.
  python3 -c "
import functools, http.server, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(sys.argv[1], sys.argv[2])
# Real camouflage sites negotiate ALPN; Xray-core >= 26.10 pads its own
# EncryptedExtensions to the target's size and rejects a smaller target.
context.set_alpn_protocols(['h2', 'http/1.1'])
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[3])
server = http.server.ThreadingHTTPServer(('127.0.0.1', 18444), handler)
server.daemon_threads = True
server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
server.serve_forever()
" "${work}/target.crt" "${work}/target.key" "${www}" > "${work}/target-dest.log" 2>&1 &
  python3 -m http.server 18080 --bind 127.0.0.1 --directory "${www}" > "${work}/target-http.log" 2>&1 &
  # UDP echo target for UDP-over-TCP relays.
  python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 18053))
while True:
    data, peer = sock.recvfrom(65535)
    sock.sendto(data, peer)
" > "${work}/target-udp.log" 2>&1 &

  local keypair private_key public_key uuid short_id server_name hy2_password hy2_obfs_password tuic_password
  keypair="$("${bin}/sing-box" generate reality-keypair)"
  private_key="$(awk '/PrivateKey/ {print $2}' <<<"${keypair}")"
  public_key="$(awk '/PublicKey/ {print $2}' <<<"${keypair}")"
  uuid="$("${bin}/sing-box" generate uuid)"
  short_id="$(openssl rand -hex 8)"
  server_name="reality.interop.test"
  hy2_password="$(openssl rand -hex 16)"
  tuic_password="$(openssl rand -hex 16)"
  hy2_obfs_password="$(openssl rand -hex 16)"

  cat > "${work}/xray.json" <<EOF
{
  "log": {"loglevel": "debug"},
  "inbounds": [
    {"tag": "vision", "listen": "127.0.0.1", "port": 24431, "protocol": "vless",
     "settings": {"clients": [{"id": "${uuid}", "flow": "xtls-rprx-vision"}], "decryption": "none"},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"dest": "127.0.0.1:18444", "serverNames": ["${server_name}"],
         "privateKey": "${private_key}", "shortIds": ["${short_id}"], "show": true}}},
    {"tag": "plain", "listen": "127.0.0.1", "port": 24432, "protocol": "vless",
     "settings": {"clients": [{"id": "${uuid}"}], "decryption": "none"},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"dest": "127.0.0.1:18444", "serverNames": ["${server_name}"],
         "privateKey": "${private_key}", "shortIds": ["${short_id}"], "show": true}}},
    {"tag": "vmess-tcp", "listen": "127.0.0.1", "port": 24441, "protocol": "vmess",
     "settings": {"clients": [{"id": "${uuid}"}]}},
    {"tag": "vmess-ws", "listen": "127.0.0.1", "port": 24442, "protocol": "vmess",
     "settings": {"clients": [{"id": "${uuid}"}]},
     "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}}},
    {"tag": "vmess-grpc", "listen": "127.0.0.1", "port": 24443, "protocol": "vmess",
     "settings": {"clients": [{"id": "${uuid}"}]},
     "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "vmgrpc"}}}
  ],
  "outbounds": [{"protocol": "freedom",
    "settings": {"finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1"]}]}}]
}
EOF

  cat > "${work}/sing-box.json" <<EOF
{
  "log": {"level": "debug"},
  "inbounds": [
    {"type": "vless", "tag": "vision", "listen": "127.0.0.1", "listen_port": 25431,
     "users": [{"uuid": "${uuid}", "flow": "xtls-rprx-vision"}],
     "tls": {"enabled": true, "server_name": "${server_name}",
       "reality": {"enabled": true, "handshake": {"server": "127.0.0.1", "server_port": 18444},
         "private_key": "${private_key}", "short_id": ["${short_id}"]}}},
    {"type": "vless", "tag": "plain", "listen": "127.0.0.1", "listen_port": 25432,
     "users": [{"uuid": "${uuid}", "flow": ""}],
     "tls": {"enabled": true, "server_name": "${server_name}",
       "reality": {"enabled": true, "handshake": {"server": "127.0.0.1", "server_port": 18444},
         "private_key": "${private_key}", "short_id": ["${short_id}"]}}},
    {"type": "vmess", "tag": "vmess-tcp", "listen": "127.0.0.1", "listen_port": 25441,
     "users": [{"uuid": "${uuid}", "alterId": 0}]},
    {"type": "vmess", "tag": "vmess-ws", "listen": "127.0.0.1", "listen_port": 25442,
     "users": [{"uuid": "${uuid}", "alterId": 0}],
     "transport": {"type": "ws", "path": "/vm"}},
    {"type": "vmess", "tag": "vmess-grpc", "listen": "127.0.0.1", "listen_port": 25443,
     "users": [{"uuid": "${uuid}", "alterId": 0}],
     "transport": {"type": "grpc", "service_name": "vmgrpc"}},
    {"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": 26441,
     "users": [{"password": "${hy2_password}"}],
     "tls": {"enabled": true, "alpn": ["h3"],
       "certificate_path": "${work}/target.crt", "key_path": "${work}/target.key"}},
    {"type": "hysteria2", "tag": "hy2-salamander", "listen": "127.0.0.1", "listen_port": 26442,
     "users": [{"password": "${hy2_password}"}],
     "obfs": {"type": "salamander", "password": "${hy2_obfs_password}"},
     "tls": {"enabled": true, "alpn": ["h3"],
       "certificate_path": "${work}/target.crt", "key_path": "${work}/target.key"}},
    {"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": 26451,
     "users": [{"uuid": "${uuid}", "password": "${tuic_password}"}],
     "congestion_control": "bbr",
     "tls": {"enabled": true, "alpn": ["h3"],
       "certificate_path": "${work}/target.crt", "key_path": "${work}/target.key"}}
  ],
  "outbounds": [{"type": "direct"}]
}
EOF

  # Xray-core >= 26.5 blackholes private targets from VLESS inbounds unless a
  # freedom finalRules entry allows them; the test targets live on loopback.
  "${bin}/xray" run -c "${work}/xray.json" > "${work}/xray.log" 2>&1 &
  "${bin}/sing-box" run -c "${work}/sing-box.json" > "${work}/sing-box.log" 2>&1 &

  # The reference Hysteria2 server.
  cat > "${work}/hysteria.yaml" <<EOF
listen: 127.0.0.1:27441
tls:
  cert: ${work}/target.crt
  key: ${work}/target.key
auth:
  type: password
  password: ${hy2_password}
EOF
  "${bin}/hysteria" server -c "${work}/hysteria.yaml" > "${work}/hysteria.log" 2>&1 &
  cat > "${work}/hysteria-salamander.yaml" <<EOF
listen: 127.0.0.1:27442
tls:
  cert: ${work}/target.crt
  key: ${work}/target.key
auth:
  type: password
  password: ${hy2_password}
obfs:
  type: salamander
  salamander:
    password: ${hy2_obfs_password}
EOF
  "${bin}/hysteria" server -c "${work}/hysteria-salamander.yaml" > "${work}/hysteria-salamander.log" 2>&1 &

  for port in 18080 18443 18444 24431 24432 24441 24442 24443 25431 25432 25441 25442 25443; do
    wait_for_port "${port}"
  done
  for port in 26441 26442 26451 27441 27442 18053; do
    wait_for_udp_port "${port}"
  done

  # Official snell-server instances: name=host:port:version:mode:obfs.
  local snell_psk snell_servers="" snell_port=28400
  snell_psk="$(openssl rand -hex 16)"
  start_snell() {
    local server_version="$1" name="$2" version="$3" mode="$4" obfs="$5"
    local binary="${bin}/snell-server-${server_version}"
    [[ -x "${binary}" ]] || return 0
    snell_port=$((snell_port + 1))
    local conf="${work}/snell-${name}.conf"
    {
      echo "[snell-server]"
      echo "listen = 127.0.0.1:${snell_port}"
      echo "psk = ${snell_psk}"
      if [[ "${mode}" != "-" ]]; then echo "mode = ${mode}"; fi
      if [[ "${obfs}" != "none" ]]; then echo "obfs = ${obfs}"; fi
    } > "${conf}"
    "${binary}" -l info -c "${conf}" > "${work}/snell-${name}.log" 2>&1 &
    wait_for_port "${snell_port}"
    snell_servers+="${snell_servers:+,}${name}=127.0.0.1:${snell_port}:${version}:${mode}:${obfs}"
  }
  start_snell v3.0.1 snell-v3 3 - none
  start_snell v3.0.1 snell-v3-http 3 - http
  start_snell v4.1.1 snell-v4 4 - none
  start_snell v4.1.1 snell-v4-http 4 - http
  start_snell v5.0.1 snell-v5 4 - none
  start_snell v6.0.0rc2 snell-v6-default 6 default none
  start_snell v6.0.0rc2 snell-v6-unshaped 6 unshaped none
  start_snell v6.0.0rc2 snell-v6-unsafe-raw 6 unsafe-raw none

  # TCP echo target.
  python3 -c "
import socketserver
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(('127.0.0.1', 18090), Echo).serve_forever()
" > "${work}/target-echo.log" 2>&1 &
  wait_for_port 18090

  # Official mita server (systemd service from the release package).
  local mieru_user mieru_password
  mieru_user="interop$(openssl rand -hex 3)"
  mieru_password="$(openssl rand -hex 16)"
  sudo dpkg -i "${work}/mita.deb" > "${work}/mita-install.log" 2>&1
  sudo systemctl start mita
  cat > "${work}/mita.json" <<JSON
{
  "portBindings": [
    {"port": 28501, "protocol": "TCP"},
    {"portRange": "28510-28512", "protocol": "TCP"}
  ],
  "users": [
    {"name": "${mieru_user}", "password": "${mieru_password}", "allowLoopbackIP": true}
  ],
  "loggingLevel": "INFO",
  "dns": {"dualStack": "PREFER_IPv4", "hosts": {"mieru.interop.test": "127.0.0.1"}}
}
JSON
  for _ in $(seq 1 50); do
    sudo mita status > /dev/null 2>&1 && break
    sleep 0.2
  done
  sudo mita apply config "${work}/mita.json"
  sudo mita start
  for port in 28501 28510 28511 28512; do
    wait_for_port "${port}"
  done

  # iwand-server in no-exit mode: it forwards packets between sessions by
  # destination address and echoes the rest. "plain" may not mask.
  local iwan_plain_password iwan_xor_password
  iwan_plain_password="$(openssl rand -hex 8)"
  iwan_xor_password="$(openssl rand -hex 8)"
  cat > "${work}/iwand.json" <<JSON
{
  "listen": "127.0.0.1:28601",
  "mtu": 1380,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "users": [
    {"username": "plain", "password": "${iwan_plain_password}", "address": "10.20.30.10", "allow_encrypt": false},
    {"username": "xor", "password": "${iwan_xor_password}", "address": "10.20.30.11"}
  ]
}
JSON
  "${bin}/iwand-server" -config "${work}/iwand.json" > "${work}/iwand-server.log" 2>&1 &
  wait_for_udp_port 28601

  cat > "${work}/env" <<EOF
NC_INTEROP_SERVERS=xray-vision=127.0.0.1:24431:vision,xray-plain=127.0.0.1:24432:none,sing-box-vision=127.0.0.1:25431:vision,sing-box-plain=127.0.0.1:25432:none
NC_VLESS_UUID=${uuid}
NC_VMESS_SERVERS=xray-vmess-tcp=127.0.0.1:24441:tcp,xray-vmess-ws=127.0.0.1:24442:ws,xray-vmess-grpc=127.0.0.1:24443:grpc,sing-box-vmess-tcp=127.0.0.1:25441:tcp,sing-box-vmess-ws=127.0.0.1:25442:ws,sing-box-vmess-grpc=127.0.0.1:25443:grpc
NC_VMESS_UUID=${uuid}
NC_HYSTERIA2_SERVERS=sing-box=127.0.0.1:26441,hysteria=127.0.0.1:27441,sing-box-salamander=127.0.0.1:26442:salamander,hysteria-salamander=127.0.0.1:27442:salamander
NC_HYSTERIA2_OBFS_PASSWORD=${hy2_obfs_password}
NC_HYSTERIA2_PASSWORD=${hy2_password}
NC_HYSTERIA2_SERVER_NAME=target.interop.test
NC_TUIC_SERVERS=sing-box=127.0.0.1:26451
NC_TUIC_UUID=${uuid}
NC_TUIC_PASSWORD=${tuic_password}
NC_TUIC_SERVER_NAME=target.interop.test
NC_REALITY_PUBLIC_KEY=${public_key}
NC_REALITY_PRIVATE_KEY=${private_key}
NC_REALITY_DEST=127.0.0.1:18444
NC_INTEROP_BIN=${bin}
NC_SERVER_CERT=${work}/server.crt
NC_SERVER_KEY=${work}/server.key
NC_SERVER_NAME=server.interop.test
NC_REALITY_SHORT_ID=${short_id}
NC_REALITY_SERVER_NAME=${server_name}
NC_HTTP_TARGET=127.0.0.1:18080
NC_TLS_TARGET=127.0.0.1:18443
NC_SNELL_SERVERS=${snell_servers}
NC_SNELL_PSK=${snell_psk}
NC_UDP_ECHO=127.0.0.1:18053
NC_TCP_ECHO=127.0.0.1:18090
NC_MIERU_SERVER=127.0.0.1:28501
NC_MIERU_PORT_RANGE=28510-28512
NC_MIERU_USER=${mieru_user}
NC_MIERU_PASSWORD=${mieru_password}
NC_MIERU_DOMAIN=mieru.interop.test
NC_IWAN_SERVER=127.0.0.1:28601
NC_IWAN_PLAIN=plain:${iwan_plain_password}:10.20.30.10
NC_IWAN_XOR=xor:${iwan_xor_password}:10.20.30.11
NC_IWAN_DNS=1.1.1.1,8.8.8.8
NC_IWAN_MTU=1380
EOF
}

logs() {
  local log
  for log in xray sing-box hysteria hysteria-salamander target-tls target-dest target-http target-udp target-echo mita-install iwand-server; do
    if [[ -f "${work}/${log}.log" ]]; then
      echo "::group::${log}.log"
      tail -n 200 "${work}/${log}.log"
      echo "::endgroup::"
    fi
  done
  for log in "${work}"/snell-*.log; do
    [[ -f "${log}" ]] || continue
    echo "::group::$(basename "${log}")"
    tail -n 200 "${log}"
    echo "::endgroup::"
  done
  if systemctl list-unit-files mita.service > /dev/null 2>&1; then
    echo "::group::mita journal"
    sudo journalctl -u mita --no-pager | tail -n 200 || true
    echo "::endgroup::"
  fi
}

case "${1:-}" in
  download) download ;;
  start) start ;;
  logs) logs ;;
  *) echo "usage: $0 download|start|logs" >&2; exit 2 ;;
esac
