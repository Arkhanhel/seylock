#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
"""A second, independent implementation of endpoint list acceptance.

Written from PROTOCOL.md alone, with nothing but the Python standard library:
Ed25519 verification follows the reference code of RFC 8032, and the document
rules follow PROTOCOL.md section 1. It shares no code, no cryptography library
and no JSON parser with the Rust implementation. If both agree on every
vector in test-vectors/endpoints.json, the protocol document is precise enough
to build a compatible client from.

    python3 -I tools/verify_vectors.py [test-vectors/endpoints.json]

Exits with 0 when every vector gives its expected result.
"""

import base64
import binascii
import hashlib
import json
import sys

# --- Ed25519 verification (RFC 8032, section 5.1) ---------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _add(a, b):
    # Extended coordinates (X, Y, Z, T), RFC 8032 section 5.1.4.
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _compress(point):
    zinv = pow(point[2], P - 2, P)
    x = point[0] * zinv % P
    y = point[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


_GY = 4 * pow(5, P - 2, P) % P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % P)


def ed25519_public_key_ok(key):
    return _decompress(key) is not None


def ed25519_verify(key, message, signature):
    """Cofactorless check: encode([S]B - [k]A) == R, with S < L."""
    a = _decompress(key)
    if a is None or len(signature) != 64:
        return False
    r = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(r + key + message).digest(), "little") % L
    neg_a = ((P - a[0]) % P, a[1], a[2], (P - a[3]) % P)
    return _compress(_add(_mul(s, _G), _mul(k, neg_a))) == r


# --- Endpoint lists (PROTOCOL.md section 1) ---------------------------------

CONTEXT_V1 = b"secretly-endpoints-v1\n"
CONTEXT_V2 = b"transport-endpoints-v2\n"
CLOCK_SKEW_MS = 7 * 24 * 60 * 60 * 1000
MAX_SERVICES = 16
MAX_TOR_BRIDGES = 32
MAX_TOR_BRIDGE_LEN = 2048
NAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


class Reject(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _b64(text):
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise Reject(2)


def _int(value, lo, hi):
    return isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi


def _str_map(value):
    return isinstance(value, dict) and all(isinstance(v, str) for v in value.values())


def _opt_str(obj, field):
    return obj.get(field) is None or isinstance(obj.get(field), str)


def _parse_path(p):
    """Structural rules of a path; unknown fields are ignored."""
    if not isinstance(p, dict) or not isinstance(p.get("kind"), str):
        raise Reject(4)
    kind = p["kind"]
    if kind in ("direct", "tor"):
        return
    if kind == "ip":
        ok = isinstance(p.get("ip"), str)
    elif kind in ("mirror", "cdn"):
        ok = _opt_str(p, "keys") and _opt_str(p, "relay")
        ok = ok and ("targets" not in p or _str_map(p["targets"]))
        if kind == "mirror":
            ok = ok and _opt_str(p, "ip")
    elif kind == "proxy":
        ok = isinstance(p.get("host"), str)
        ok = ok and ("port" not in p or _int(p["port"], 0, 65535))
    elif kind == "socks":
        ok = isinstance(p.get("addr"), str)
    else:
        ok = False
    if not ok:
        raise Reject(4)


def _parse_document(doc):
    try:
        d = json.loads(doc)
    except ValueError:
        raise Reject(4)
    if not isinstance(d, dict):
        raise Reject(4)
    if not _int(d.get("v"), 0, 2**32 - 1):
        raise Reject(4)
    for field in ("issued_at_ms", "expires_at_ms"):
        if not _int(d.get(field), -(2**63), 2**63 - 1):
            raise Reject(4)
    logical = d.get("logical")
    if logical is not None and not (
        isinstance(logical, dict)
        and isinstance(logical.get("keys"), str)
        and isinstance(logical.get("relay"), str)
    ):
        raise Reject(4)
    if "services" in d and not _str_map(d["services"]):
        raise Reject(4)
    if "tor_bridges" in d and not (
        isinstance(d["tor_bridges"], list)
        and all(isinstance(b, str) for b in d["tor_bridges"])
    ):
        raise Reject(4)
    if not isinstance(d.get("paths"), list):
        raise Reject(4)
    for p in d["paths"]:
        _parse_path(p)
    return d


def _valid_name(name):
    return 1 <= len(name) <= 32 and name[0] != "-" and set(name) <= NAME_CHARS


def _check_shape(d):
    paths = d["paths"]
    services = d.get("services") or {}
    webby = [p for p in paths if p["kind"] in ("mirror", "cdn")]
    bridges = d.get("tor_bridges") or []
    if d["v"] == 1:
        if services or bridges:
            raise Reject(4)
        for p in webby:
            if p.get("keys") is None or p.get("relay") is None or p.get("targets"):
                raise Reject(4)
        logical = d.get("logical")
        if logical is None or not paths or not logical["keys"] or not logical["relay"]:
            raise Reject(8)
        return
    if d.get("logical") is not None:
        raise Reject(4)
    for p in webby:
        if p.get("keys") is not None or p.get("relay") is not None or not p.get("targets"):
            raise Reject(4)
    if not paths or not services or any(v == "" for v in services.values()):
        raise Reject(8)
    if len(services) > MAX_SERVICES or not all(_valid_name(n) for n in services):
        raise Reject(9)
    for p in webby:
        for name, base in p["targets"].items():
            if name not in services or base == "":
                raise Reject(10)
    def bridge_ok(b):
        raw = b.encode("utf-8")
        return 1 <= len(raw) <= MAX_TOR_BRIDGE_LEN and all(0x20 <= c <= 0x7E for c in raw)
    if len(bridges) > MAX_TOR_BRIDGES or not all(bridge_ok(b) for b in bridges):
        raise Reject(11)


def accept(signed_json, public_key_b64, now_ms, current_issued_at_ms):
    """Returns 0 if the list is accepted, otherwise the rejection code."""
    try:
        try:
            env = json.loads(signed_json)
        except ValueError:
            raise Reject(1)
        if not (
            isinstance(env, dict)
            and isinstance(env.get("doc"), str)
            and isinstance(env.get("sig_b64"), str)
        ):
            raise Reject(1)
        key = _b64(public_key_b64)
        if len(key) != 32 or not ed25519_public_key_ok(key):
            raise Reject(2)
        sig = _b64(env["sig_b64"])
        if len(sig) != 64:
            raise Reject(2)
        doc = env["doc"].encode("utf-8")
        if ed25519_verify(key, CONTEXT_V1 + doc, sig):
            signed_as = 1
        elif ed25519_verify(key, CONTEXT_V2 + doc, sig):
            signed_as = 2
        else:
            raise Reject(3)
        d = _parse_document(env["doc"])
        if d["v"] not in (1, 2):
            raise Reject(5)
        if d["v"] != signed_as:
            raise Reject(3)
        if d["expires_at_ms"] <= now_ms or d["issued_at_ms"] > now_ms + CLOCK_SKEW_MS:
            raise Reject(6)
        if d["issued_at_ms"] <= current_issued_at_ms:
            raise Reject(7)
        _check_shape(d)
        return 0
    except Reject as r:
        return r.code


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "test-vectors/endpoints.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    failures = []
    for v in data["vectors"]:
        got = accept(
            v["signed"],
            v.get("public_key_b64", data["public_key_b64"]),
            v["now_ms"],
            v["current_issued_at_ms"],
        )
        if got != v["expect"]:
            failures.append(f"{v['name']}: expected {v['expect']}, got {got}")
    for line in failures:
        print("FAIL", line)
    print(f"{len(data['vectors']) - len(failures)}/{len(data['vectors'])} vectors agree")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
