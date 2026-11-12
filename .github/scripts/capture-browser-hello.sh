#!/usr/bin/env bash
# Records the first ClientHello of one browser for the browser-fingerprints
# workflow: starts tls-mimic's fp_capture on 127.0.0.1:8443, opens
# https://fp.example.test:8443/ with the given command (the host name must map
# to 127.0.0.1 in /etc/hosts), and stops the browser once the capture is in.
#
# usage: capture-browser-hello.sh <name> <output dir> <command> [args...]
# FP_CAPTURE names the fp_capture binary.
set -euo pipefail

name="$1"
out="$2"
shift 2
mkdir -p "${out}"
url="https://fp.example.test:8443/"

"${FP_CAPTURE}" 127.0.0.1:8443 "${out}/${name}.hex" 90 >"${out}/${name}.log" 2>&1 &
capture=$!
sleep 1

# A process group of its own, so every helper process stops with it.
if command -v setsid >/dev/null 2>&1; then
  setsid "$@" "${url}" >"${out}/${name}.browser.log" 2>&1 &
else
  "$@" "${url}" >"${out}/${name}.browser.log" 2>&1 &
fi
browser=$!

status=0
wait "${capture}" || status=$?
kill -TERM -- "-${browser}" 2>/dev/null || kill -TERM "${browser}" 2>/dev/null || true
sleep 1
kill -KILL -- "-${browser}" 2>/dev/null || kill -KILL "${browser}" 2>/dev/null || true
wait "${browser}" 2>/dev/null || true

echo "::group::${name}"
cat "${out}/${name}.log"
if [ "${status}" -ne 0 ]; then
  echo "--- browser output"
  tail -n 40 "${out}/${name}.browser.log" || true
fi
echo "::endgroup::"
exit "${status}"
