#!/usr/bin/env python3
"""Decrypt a relay.py capture of a Mieru TCP session (test credentials only).

Derives the key the way docs/protocols/mieru.md describes, finds the nonce in
each direction, tries the candidate nonce-increment rules and prints every
segment's metadata and the start of its decrypted payload.
Usage: decode.py LOG_FILE USERNAME PASSWORD
"""
import collections
import hashlib
import json
import struct
import sys

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as aead_open
from nacl.exceptions import CryptoError

log_path, user, password = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
NAMES = {2: "openSessionRequest", 3: "openSessionResponse", 4: "closeSessionRequest",
         5: "closeSessionResponse", 6: "dataC2S", 7: "dataS2C", 8: "ackC2S", 9: "ackS2C",
         10: "dataC2S-lowEntropy", 11: "dataS2C-lowEntropy"}


def keys(t):
    hashed = hashlib.sha256(password + b"\0" + user).digest()
    out = []
    for base in sorted({int(round(t / 120.0)) * 120, int(t // 120) * 120}):
        for delta in (0, -120, 120):
            salt = hashlib.sha256(struct.pack(">Q", base + delta)).digest()
            out.append((f"{base + delta}", hashlib.pbkdf2_hmac("sha256", hashed, salt, 64, 32)))
    return out


def inc(nonce, rule, count):
    width, order = int(rule[2:]), rule[:2]
    head, tail = (nonce[:width], nonce[width:])
    if order == "be":
        value = (int.from_bytes(head, "big") + count) % (1 << (8 * width))
        return value.to_bytes(width, "big") + tail
    value = (int.from_bytes(head, "little") + count) % (1 << (8 * width))
    return value.to_bytes(width, "little") + tail


RULES = ["be24", "le24", "be20", "le20", "be16", "le16", "le8", "be8"]


def try_open(key, nonce, ct):
    try:
        return aead_open(ct, None, nonce, key)
    except CryptoError:
        return None


def locate(stream, t, label):
    hint_hits = []
    for p in range(0, min(len(stream) - 72, 4096)):
        n = stream[p:p + 24]
        if hashlib.sha256(user + n[:16]).digest()[:4] == n[20:24]:
            hint_hits.append(p)
    for p in hint_hits + list(range(0, min(len(stream) - 72, 1024))):
        n = stream[p:p + 24]
        for salt, key in keys(t):
            for first in (0, 1):
                for rule in RULES:
                    m = try_open(key, inc(n, rule, first), stream[p + 24:p + 72])
                    if m is not None:
                        print(f"[{label}] nonce at offset {p} (padding0={p} bytes), user hint present={p in hint_hits}, "
                              f"time salt={salt}, first op uses nonce+{first} (rule {rule})")
                        return p, key, n, first
    print(f"[{label}] no decryptable first segment found (hint hits {hint_hits[:5]})")
    return None


def walk(stream, label, located):
    p, key, n, first = located
    pos, op = p + 24, first
    rule = None
    segments = 0
    while pos + 48 <= len(stream) and segments < 400:
        meta = None
        candidates = [rule] if rule else RULES
        for r in candidates:
            meta = try_open(key, inc(n, r, op), stream[pos:pos + 48])
            if meta is not None:
                if rule is None and op > first:
                    print(f"[{label}] nonce increment rule = {r}")
                rule = rule or (r if op > first else None)
                break
        if meta is None:
            print(f"[{label}] segment {segments}: metadata at {pos} did not decrypt (op {op}); stop")
            return
        op += 1
        ptype = meta[0]
        if ptype in (2, 3, 4, 5):
            ts, sid, seq = struct.unpack(">IIi", meta[2:14])
            status, plen, suffix = meta[14], struct.unpack(">H", meta[15:17])[0], meta[17]
            prefix = 0
            desc = f"ts={ts} sid={sid:#x} seq={seq} status={status} plen={plen} suffix={suffix} rest={meta[18:].hex()} byte1={meta[1]}"
        else:
            ts, sid, seq, unack, win = struct.unpack(">IIIIH", meta[2:20])
            frag, prefix, plen, suffix = meta[20], meta[21], struct.unpack(">H", meta[22:24])[0], meta[24]
            desc = (f"mode={meta[1]} ts={ts} sid={sid:#x} seq={seq} unack={unack} win={win} frag={frag} "
                    f"prefix={prefix} plen={plen} suffix={suffix} tail={meta[25:].hex()}")
        print(f"[{label}] seg {segments} @{pos} {NAMES.get(ptype, ptype)}: {desc}")
        pos += 48 + prefix
        if plen:
            body = stream[pos:pos + plen + 16]
            plain = None
            for r in ([rule] if rule else RULES):
                plain = try_open(key, inc(n, r, op), body)
                if plain is not None:
                    if rule is None:
                        print(f"[{label}] nonce increment rule = {r}")
                        rule = r
                    break
            if plain is None:
                print(f"[{label}]     payload ({plen}) did not decrypt; raw head {body[:32].hex()}")
            else:
                print(f"[{label}]     payload {len(plain)}: {plain[:96].hex()}  {plain[:96]!r}")
            op += 1
            pos += plen + 16
        pos += suffix
        segments += 1
    print(f"[{label}] parsed {segments} segments, {len(stream) - pos} trailing bytes")


streams = collections.defaultdict(bytearray)
first_t = {}
for line in open(log_path):
    rec = json.loads(line)
    k = (rec["conn"], rec["dir"])
    first_t.setdefault(k, rec["t"])
    if "hex" in rec:
        streams[k] += bytes.fromhex(rec["hex"])
for k in sorted(streams):
    label = f"conn{k[0]} {k[1]}"
    s = bytes(streams[k])
    print(f"=== {label}: {len(s)} bytes, head {s[:64].hex()}")
    found = locate(s, first_t[k], label)
    if found:
        walk(s, label, found)
