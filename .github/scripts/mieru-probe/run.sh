#!/usr/bin/env bash
# Black-box Mieru wire probe (CI only). Runs the official mita server and
# mieru client from the enfein/mieru GitHub release (never redistributed),
# records the traffic between them with relay.py and decrypts it with the
# per-run test credentials via decode.py.
set -euo pipefail
: "${RUNNER_TEMP:?}"
here="$(cd "$(dirname "$0")" && pwd)"
work="${RUNNER_TEMP}/mieru-probe"
mkdir -p "${work}"
cd "${work}"
tag="${MIERU_VERSION:-v3.39.0}"
gh release download "${tag}" -R enfein/mieru -p "mita_${tag#v}_amd64.deb" -p "mieru_${tag#v}_linux_amd64.tar.gz" --clobber
sudo dpkg -i "mita_${tag#v}_amd64.deb"
tar -xzf "mieru_${tag#v}_linux_amd64.tar.gz"
mieru="${work}/mieru"
"${mieru}" version || true
pip install --quiet pynacl

user="probe$(openssl rand -hex 3)"
pass="$(openssl rand -hex 12)"
cat > server.json <<JSON
{"portBindings":[{"port":29001,"protocol":"TCP"}],
 "users":[{"name":"${user}","password":"${pass}","allowLoopbackIP":true,"allowPrivateIP":true}],
 "loggingLevel":"DEBUG","mtu":1400}
JSON
sudo systemctl start mita || true
sleep 2
sudo mita apply config server.json
sudo mita start
sudo mita status || true

mkdir -p www && head -c 3000 /dev/urandom | base64 > www/hello.txt
(cd www && python3 -m http.server 29020 --bind 127.0.0.1 >/dev/null 2>&1 &)
python3 -c 'import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",29030));s.listen()
def h(c):
  while (d:=c.recv(65536)): c.sendall(d)
  c.close()
while True:
  c,_=s.accept();threading.Thread(target=h,args=(c,),daemon=True).start()' &

scenario() {
  local name="$1" handshake="$2" mux="$3" relay_port="$4"
  local log="${work}/${name}.jsonl"
  python3 "${here}/relay.py" "${relay_port}" 29001 "${log}" &
  local relay_pid=$!
  cat > "client-${name}.json" <<JSON
{"profiles":[{"profileName":"p","user":{"name":"${user}","password":"${pass}"},
  "servers":[{"ipAddress":"127.0.0.1","portBindings":[{"port":${relay_port},"protocol":"TCP"}]}],
  "mtu":1400,"multiplexing":{"level":"${mux}"},"handshakeMode":"${handshake}"}],
 "activeProfile":"p","rpcPort":29011,"socks5Port":29010,"loggingLevel":"DEBUG"}
JSON
  "${mieru}" replace config "client-${name}.json"
  "${mieru}" start
  sleep 1
  echo "### ${name}: curl by IP"
  curl -sS --max-time 20 --socks5 127.0.0.1:29010 http://127.0.0.1:29020/hello.txt | sha256sum || true
  echo "### ${name}: curl by hostname"
  curl -sS --max-time 20 --socks5-hostname 127.0.0.1:29010 http://localhost:29020/hello.txt | sha256sum || true
  echo "### ${name}: echo 40000 bytes"
  python3 - <<'PY' || true
import socket, os, struct
s = socket.create_connection(("127.0.0.1", 29010), timeout=20)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 29030))
r = s.recv(10); print("socks reply", r.hex())
data = os.urandom(40000); s.sendall(data)
got = b""
while len(got) < len(data):
    chunk = s.recv(65536)
    if not chunk: break
    got += chunk
print("echo ok" if got == data else f"echo mismatch {len(got)}")
s.close()
PY
  sleep 1
  "${mieru}" stop || true
  sleep 1
  kill "${relay_pid}" || true
  echo "### ${name}: decode"
  python3 "${here}/decode.py" "${log}" "${user}" "${pass}" || true
}

sha256sum www/hello.txt
scenario standard HANDSHAKE_STANDARD MULTIPLEXING_OFF 29000
scenario nowait HANDSHAKE_NO_WAIT MULTIPLEXING_OFF 29002
scenario mux HANDSHAKE_STANDARD MULTIPLEXING_HIGH 29004
sudo journalctl -u mita --no-pager | tail -n 80 || true
