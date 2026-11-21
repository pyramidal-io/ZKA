#!/usr/bin/env python3
"""TEST-ONLY issuer signatures for the ZKACredential TXE tests.

ZKACredential.bind_credential accepts a credential only with an ECDSA
secp256k1 signature, by the pinned issuer key, over the SHA-256 digest of the
issuance transcript (zka_aztec_lib::issuance_transcript). TXE cannot sign with
an arbitrary secp256k1 key, so the tests embed signatures produced here.

The two keys are derived from public labels. They are TEST-ONLY and must never
be pinned in a deployment.

    issuer_test_signatures.py pubkey trusted
    issuer_test_signatures.py sign trusted CHAIN VERSION CONTRACT CC DATA A0 A1 A2 A3
    issuer_test_signatures.py digest CHAIN VERSION CONTRACT CC DATA A0 A1 A2 A3
    issuer_test_signatures.py apply FILE.nr... < txe-output

Integer arguments accept decimal or 0x-hex. Output is a Noir array literal.
Signatures use RFC 6979 nonces and low-s form, so output is deterministic.

The signatures depend on the TXE contract address, which changes with any
ZKACredential bytecode change. A stale vector fails its test with a line
`stale-issuer-vector NAME KEY CHAIN VERSION CONTRACT CC DATA A0 A1 A2 A3`.
`apply` reads TXE output on stdin, signs each such line, and rewrites
`global NAME: [u8; 64] = [...];` in the given files. Setup vectors hide the
ones behind them, so repeat until no stale line remains:

    ./aztec/scripts/txe-test.sh 2>&1 | python3 aztec/scripts/issuer_test_signatures.py apply \\
        aztec/zka_credential_aztec/src/test.nr aztec/zka_transfer_aztec/src/test.nr
"""

from __future__ import annotations

import hashlib
import hmac
import re
import sys
from pathlib import Path

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
BN254_R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

TAG = b"zka/aztec/credential-issuance/v1"
assert len(TAG) == 32

KEY_LABELS = {
    "trusted": b"zka/aztec/issuer-test-key/v1/trusted",
    "untrusted": b"zka/aztec/issuer-test-key/v1/untrusted",
}


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, point=G):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, point)
        point = _add(point, point)
        k >>= 1
    return acc


def secret_key(name: str) -> int:
    d = int.from_bytes(hashlib.sha256(KEY_LABELS[name]).digest(), "big") % N
    assert d != 0
    return d


def _rfc6979_nonce(d: int, digest: bytes) -> int:
    x = d.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(d: int, digest: bytes) -> bytes:
    z = int.from_bytes(digest, "big") % N
    k = _rfc6979_nonce(d, digest)
    r = _mul(k)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    assert r and s
    if s > N // 2:
        s = N - s
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert verify(_mul(d), signature, digest)
    return signature


def verify(public, signature: bytes, digest: bytes) -> bool:
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(digest, "big") % N
    w = pow(s, -1, N)
    point = _add(_mul(z * w % N), _mul(r * w % N, public))
    return point is not None and point[0] % N == r


def transcript(values: list[int]) -> bytes:
    if len(values) != 9:
        raise SystemExit("expected CHAIN VERSION CONTRACT CC DATA A0 A1 A2 A3")
    out = bytearray(TAG)
    for value in values:
        if value < 0 or value >= BN254_R:
            raise SystemExit("not a canonical BN254 field element: " + hex(value))
        out.extend(value.to_bytes(32, "big"))
    assert len(out) == 320
    return bytes(out)


def hex_bytes(data: bytes) -> str:
    return ", ".join("0x" + format(b, "02x") for b in data)


def noir_array(data: bytes) -> str:
    return "[" + hex_bytes(data) + "]"


def noir_global_body(data: bytes) -> str:
    rows = [data[i : i + 16] for i in range(0, len(data), 16)]
    lines = ["    " + hex_bytes(row) + "," for row in rows]
    return "[\n" + "\n".join(lines) + "\n]"


STALE_LINE = re.compile(r"stale-issuer-vector (SIG_[A-Z0-9_]+) (trusted|untrusted)((?: \S+){9})")


def apply(paths: list[str], log: str) -> int:
    signatures: dict[str, bytes] = {}
    for name, key, values in STALE_LINE.findall(log):
        digest = hashlib.sha256(transcript([int(v, 0) for v in values.split()])).digest()
        signature = sign(secret_key(key), digest)
        if signatures.setdefault(name, signature) != signature:
            raise SystemExit(f"{name}: two scenarios need different signatures; split the vector")
    if not signatures:
        print("no stale issuer vectors in the input")
        return 0
    pending = dict(signatures)
    for path in map(Path, paths):
        text = path.read_text(encoding="utf-8")
        for name, signature in signatures.items():
            pattern = re.compile(rf"(global {name}: \[u8; 64\] = )\[[^\]]*\];")
            text, count = pattern.subn(
                lambda m: m.group(1) + noir_global_body(signature) + ";", text
            )
            if count:
                pending.pop(name, None)
        path.write_text(text, encoding="utf-8")
    if pending:
        raise SystemExit(f"no global found for: {', '.join(sorted(pending))}")
    print("updated: " + ", ".join(sorted(signatures)) + " (re-run the tests)")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        raise SystemExit(__doc__)
    command = argv[1]
    if command == "pubkey" and len(argv) == 3:
        x, y = _mul(secret_key(argv[2]))
        print("x:", noir_array(x.to_bytes(32, "big")))
        print("y:", noir_array(y.to_bytes(32, "big")))
        return 0
    if command == "digest":
        print(noir_array(hashlib.sha256(transcript([int(v, 0) for v in argv[2:]])).digest()))
        return 0
    if command == "apply" and len(argv) >= 3:
        return apply(argv[2:], sys.stdin.read())
    if command == "sign" and len(argv) >= 3:
        digest = hashlib.sha256(transcript([int(v, 0) for v in argv[3:]])).digest()
        print(noir_array(sign(secret_key(argv[2]), digest)))
        return 0
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
