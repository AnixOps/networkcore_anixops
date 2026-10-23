#!/usr/bin/env bash
# REALITY (outbound-vless) and VMess (outbound-vmess) interop harness
# (Linux runners only).
#
#   reality-interop.sh download   fetch Xray-core and sing-box release binaries
#   reality-interop.sh start      start targets and REALITY servers, write env
#   reality-interop.sh logs       print server logs (for failed runs)
#
# Versions come from XRAY_VERSION / SINGBOX_VERSION (a release tag or
# "latest"). Keys, UUID and short id are generated per run.

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
  local xray_tag singbox_tag singbox_version
  xray_tag="$(resolve_tag XTLS/Xray-core "${XRAY_VERSION:-latest}")"
  singbox_tag="$(resolve_tag SagerNet/sing-box "${SINGBOX_VERSION:-latest}")"
  singbox_version="${singbox_tag#v}"

  gh release download "${xray_tag}" -R XTLS/Xray-core -p Xray-linux-64.zip -D "${work}" --clobber
  unzip -o -q "${work}/Xray-linux-64.zip" xray -d "${bin}"

  gh release download "${singbox_tag}" -R SagerNet/sing-box \
    -p "sing-box-${singbox_version}-linux-amd64.tar.gz" -D "${work}" --clobber
  tar -xzf "${work}/sing-box-${singbox_version}-linux-amd64.tar.gz" -C "${work}"
  cp "${work}/sing-box-${singbox_version}-linux-amd64/sing-box" "${bin}/sing-box"
  chmod +x "${bin}/xray" "${bin}/sing-box"

  "${bin}/xray" version | sed -n 1p
  "${bin}/sing-box" version | sed -n 1p
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### REALITY interop servers"
      echo
      echo "| Server | Release |"
      echo "| --- | --- |"
      echo "| Xray-core | ${xray_tag} |"
      echo "| sing-box | ${singbox_tag} |"
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

  local keypair private_key public_key uuid short_id server_name
  keypair="$("${bin}/sing-box" generate reality-keypair)"
  private_key="$(awk '/PrivateKey/ {print $2}' <<<"${keypair}")"
  public_key="$(awk '/PublicKey/ {print $2}' <<<"${keypair}")"
  uuid="$("${bin}/sing-box" generate uuid)"
  short_id="$(openssl rand -hex 8)"
  server_name="reality.interop.test"

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
     "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}}}
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
     "transport": {"type": "ws", "path": "/vm"}}
  ],
  "outbounds": [{"type": "direct"}]
}
EOF

  # Xray-core >= 26.5 blackholes private targets from VLESS inbounds unless a
  # freedom finalRules entry allows them; the test targets live on loopback.
  "${bin}/xray" run -c "${work}/xray.json" > "${work}/xray.log" 2>&1 &
  "${bin}/sing-box" run -c "${work}/sing-box.json" > "${work}/sing-box.log" 2>&1 &

  for port in 18080 18443 18444 24431 24432 24441 24442 25431 25432 25441 25442; do
    wait_for_port "${port}"
  done

  cat > "${work}/env" <<EOF
NC_INTEROP_SERVERS=xray-vision=127.0.0.1:24431:vision,xray-plain=127.0.0.1:24432:none,sing-box-vision=127.0.0.1:25431:vision,sing-box-plain=127.0.0.1:25432:none
NC_VLESS_UUID=${uuid}
NC_VMESS_SERVERS=xray-vmess-tcp=127.0.0.1:24441:tcp,xray-vmess-ws=127.0.0.1:24442:ws,sing-box-vmess-tcp=127.0.0.1:25441:tcp,sing-box-vmess-ws=127.0.0.1:25442:ws
NC_VMESS_UUID=${uuid}
NC_REALITY_PUBLIC_KEY=${public_key}
NC_REALITY_SHORT_ID=${short_id}
NC_REALITY_SERVER_NAME=${server_name}
NC_HTTP_TARGET=127.0.0.1:18080
NC_TLS_TARGET=127.0.0.1:18443
EOF
}

logs() {
  for log in xray sing-box target-tls target-dest target-http; do
    if [[ -f "${work}/${log}.log" ]]; then
      echo "::group::${log}.log"
      tail -n 200 "${work}/${log}.log"
      echo "::endgroup::"
    fi
  done
}

case "${1:-}" in
  download) download ;;
  start) start ;;
  logs) logs ;;
  *) echo "usage: $0 download|start|logs" >&2; exit 2 ;;
esac
