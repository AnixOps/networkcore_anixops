#!/usr/bin/env bash
# Soak test of the packet tunnel (tunnel_bench soak), shared by both jobs of
# .github/workflows/soak.yml. Needs sudo for the TUN device.
#
# Environment: SOAK_HOURS (fractional), MAX_SLOPE_MB_PER_H, OUTBOUND,
# CONNS_PER_S, RESULTS (directory).
set -euo pipefail

hours="${SOAK_HOURS:-5.5}"
results="${RESULTS:-results}"
minutes="$(python3 -c "import sys; print(round(float(sys.argv[1]) * 60, 2))" "${hours}")"

cargo build --locked --release -p engine-embedded --example tunnel_bench

if ! ip link show ncb0 >/dev/null 2>&1; then
  sudo ip tuntap add dev ncb0 mode tun user "$(id -u)"
  sudo ip addr add 198.18.0.1/16 dev ncb0
  sudo ip link set ncb0 mtu 1500 up
fi
cleanup() { sudo ip link delete ncb0 >/dev/null 2>&1 || true; }
trap cleanup EXIT

ulimit -n 65536 || ulimit -n "$(ulimit -Hn)"
mkdir -p "${results}"
echo "Soak: ${hours} h (${minutes} min), outbound ${OUTBOUND:-redirect}"
target/release/examples/tunnel_bench soak --tun ncb0 \
  --outbound "${OUTBOUND:-redirect}" \
  --minutes "${minutes}" \
  --sample-secs 60 \
  --conns-per-s "${CONNS_PER_S:-20}" \
  --max-conns 512 \
  --max-slope-mb-per-h "${MAX_SLOPE_MB_PER_H:-1}" \
  --json "${results}/soak.json"
