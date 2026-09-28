"""wallet_crypto.py — passphrase-based encryption for Excalibur wallet files.

Construction (all stdlib, no third-party dependencies):
  key = PBKDF2-HMAC-SHA256(passphrase, salt, 600_000 iterations, 64 bytes)
  enc_key, mac_key = key[:32], key[32:]
  ciphertext = AES-256-CTR(enc_key, iv, plaintext)
  tag = HMAC-SHA256(mac_key, iv || ciphertext)        (Encrypt-then-MAC)

The AES-256 below is a compact FIPS-197 implementation (S-box generated at
import from the GF(2^8) definition, so there is no 256-byte table to
mistranscribe); it is checked against the NIST AES-256 test vector in
test_wallet_crypto.py. Keystream blocks are AES(enc_key, iv+i) with the
128-bit big-endian counter starting at the random iv — never reuse an
(iv, enc_key) pair, which the random iv guarantees in practice.

File format (JSON, written over the plaintext wallet in place):
  {"format": "excalibur-wallet-enc-v1", "kdf": "pbkdf2-hmac-sha256",
   "iterations": 600000, "salt": hex, "iv": hex,
   "ciphertext": hex, "tag": hex}

CLI:
  python3 wallet_crypto.py genkeyfile --keyfile PATH
      Generate a random 32-byte passphrase into PATH (chmod 600).
  python3 wallet_crypto.py encrypt --wallet PATH --keyfile PATH
      Encrypt PATH in place; the plaintext is first copied to
      PATH.plaintext.bak (chmod 600), which the operator must delete.
  python3 wallet_crypto.py decrypt --wallet PATH --keyfile PATH
      Reverse of encrypt (recovery / testing): restores plaintext JSON.

The passphrase is read from the keyfile with surrounding whitespace
stripped and is never printed or logged.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys

FORMAT = "excalibur-wallet-enc-v1"
KDF = "pbkdf2-hmac-sha256"
ITERATIONS = 600_000
SALT_LEN = 16
IV_LEN = 16

# ------------------------------------------------------------------ AES-256
# FIPS-197. The S-box is derived from the field definition at import time.


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF)
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a, n):
    r = 1
    while n:
        if n & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        n >>= 1
    return r


def _sbox_init():
    sbox = [0] * 256
    for b in range(256):
        inv = 0 if b == 0 else _gf_pow(b, 254)
        # affine transform: y = inv ^ rotl(inv,1) ^ rotl(inv,2) ^
        #                  rotl(inv,3) ^ rotl(inv,4) ^ 0x63
        y = inv ^ 0x63
        x = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        sbox[b] = y
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _sbox_init()


def _sub_word(w):
    return (_SBOX[(w >> 24) & 0xFF] << 24 | _SBOX[(w >> 16) & 0xFF] << 16
            | _SBOX[(w >> 8) & 0xFF] << 8 | _SBOX[w & 0xFF])


def _rot_word(w):
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _expand_key(key):
    assert len(key) == 32
    w = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        tmp = w[i - 1]
        if i % 8 == 0:
            tmp = _sub_word(_rot_word(tmp)) ^ (rcon << 24)
            rcon = _gf_mul(rcon, 2)
        elif i % 8 == 4:
            tmp = _sub_word(tmp)
        w.append((w[i - 8] ^ tmp) & 0xFFFFFFFF)
    return w  # 60 words; round r uses w[4r:4r+4]


def _add_round_key(s, w, rnd):
    for c in range(4):
        word = w[4 * rnd + c]
        for r in range(4):
            s[r][c] ^= (word >> (24 - 8 * r)) & 0xFF


def _aes_encrypt_block(key, block16):
    s = [[block16[r + 4 * c] for c in range(4)] for r in range(4)]
    w = _expand_key(key)
    _add_round_key(s, w, 0)
    for rnd in range(1, 14):  # rounds 1..13: full rounds incl. MixColumns
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):  # ShiftRows
            s[r] = s[r][r:] + s[r][:r]
        for c in range(4):  # MixColumns
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            s[0][c] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
            s[1][c] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
            s[2][c] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
            s[3][c] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
        _add_round_key(s, w, rnd)
    # round 14: final, no MixColumns
    for r in range(4):
        for c in range(4):
            s[r][c] = _SBOX[s[r][c]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    _add_round_key(s, w, 14)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _aes_decrypt_block(key, block16):
    s = [[block16[r + 4 * c] for c in range(4)] for r in range(4)]
    w = _expand_key(key)
    _add_round_key(s, w, 14)
    for rnd in range(13, 0, -1):
        for r in range(1, 4):  # InvShiftRows
            s[r] = s[r][-r:] + s[r][:-r]
        for r in range(4):
            for c in range(4):
                s[r][c] = _INV_SBOX[s[r][c]]
        _add_round_key(s, w, rnd)
        # InvMixColumns
        for c in range(4):
            a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
            s[0][c] = (_gf_mul(a0, 14) ^ _gf_mul(a1, 11)
                       ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9))
            s[1][c] = (_gf_mul(a0, 9) ^ _gf_mul(a1, 14)
                       ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13))
            s[2][c] = (_gf_mul(a0, 13) ^ _gf_mul(a1, 9)
                       ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11))
            s[3][c] = (_gf_mul(a0, 11) ^ _gf_mul(a1, 13)
                       ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14))
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]
    for r in range(4):
        for c in range(4):
            s[r][c] = _INV_SBOX[s[r][c]]
    _add_round_key(s, w, 0)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _ctr_crypt(enc_key, iv, data):
    """AES-256-CTR encrypt/decrypt (symmetric)."""
    assert len(iv) == 16
    out = bytearray()
    ctr = int.from_bytes(iv, "big")
    for off in range(0, len(data), 16):
        ks = _aes_encrypt_block(
            enc_key, ((ctr + off // 16) % (1 << 128)).to_bytes(16, "big"))
        out.extend(b ^ k for b, k in zip(data[off:off + 16], ks))
    return bytes(out)


# ------------------------------------------------------- envelope (KDF+MAC)
def _derive(passphrase: bytes, salt: bytes, iterations: int = ITERATIONS):
    key = hashlib.pbkdf2_hmac("sha256", passphrase, salt, iterations, 64)
    return key[:32], key[32:]


def encrypt_bytes(plaintext: bytes, passphrase: bytes) -> dict:
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    enc_key, mac_key = _derive(passphrase, salt)
    ct = _ctr_crypt(enc_key, iv, plaintext)
    tag = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return {"format": FORMAT, "kdf": KDF, "iterations": ITERATIONS,
            "salt": salt.hex(), "iv": iv.hex(),
            "ciphertext": ct.hex(), "tag": tag.hex()}


def decrypt_bytes(blob: dict, passphrase: bytes) -> bytes:
    if not isinstance(blob, dict) or blob.get("format") != FORMAT:
        raise ValueError("not an excalibur encrypted wallet")
    salt = bytes.fromhex(blob["salt"])
    iv = bytes.fromhex(blob["iv"])
    ct = bytes.fromhex(blob["ciphertext"])
    tag = bytes.fromhex(blob["tag"])
    enc_key, mac_key = _derive(passphrase, salt,
                               int(blob.get("iterations", ITERATIONS)))
    expect = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise ValueError("decryption failed: wrong passphrase or "
                         "corrupted wallet file")
    return _ctr_crypt(enc_key, iv, ct)


def is_encrypted_wallet(data) -> bool:
    return isinstance(data, dict) and data.get("format") == FORMAT


# ------------------------------------------------------------------- CLI
def _read_keyfile(path) -> bytes:
    if not os.path.exists(path):
        raise SystemExit(
            f"keyfile not found: {path}\n"
            f"create one with: python3 wallet_crypto.py genkeyfile "
            f"--keyfile {path}")
    with open(path, "rb") as f:
        pw = f.read().strip()
    if not pw:
        raise SystemExit(f"keyfile is empty: {path}")
    st = os.stat(path)
    if st.st_mode & 0o077:
        print(f"warning: keyfile {path} is readable by group/other; "
              f"run: chmod 600 {path}", file=sys.stderr)
    return pw


def _chmod600(path):
    os.chmod(path, 0o600)


def cmd_genkeyfile(args):
    if os.path.exists(args.keyfile) and not args.force:
        raise SystemExit(f"refusing to overwrite existing {args.keyfile} "
                         f"(use --force)")
    pw = os.urandom(32).hex() + "\n"
    tmp = args.keyfile + ".tmp"
    with open(tmp, "w") as f:
        f.write(pw)
    _chmod600(tmp)
    os.replace(tmp, args.keyfile)
    print(f"wrote {args.keyfile} (chmod 600). "
          f"Back it up separately from the wallet.")


def cmd_encrypt(args):
    pw = _read_keyfile(args.keyfile)
    with open(args.wallet) as f:
        data = json.load(f)
    if is_encrypted_wallet(data):
        raise SystemExit(f"{args.wallet} is already encrypted; refusing.")
    if not (isinstance(data, dict) and "priv" in data and "pub" in data):
        raise SystemExit(f"{args.wallet} does not look like a plaintext "
                         f"Excalibur wallet.")
    bak = args.wallet + ".plaintext.bak"
    if os.path.exists(bak) and not args.force:
        raise SystemExit(f"backup {bak} already exists; refusing to "
                         f"overwrite (use --force).")
    with open(bak, "w") as f:
        json.dump(data, f)
    _chmod600(bak)
    blob = encrypt_bytes(json.dumps(data).encode(), pw)
    tmp = args.wallet + ".tmp"
    with open(tmp, "w") as f:
        json.dump(blob, f)
    _chmod600(tmp)
    os.replace(tmp, args.wallet)
    print(f"encrypted {args.wallet} in place.")
    print(f"plaintext backup at {bak} — DELETE it once you have verified "
          f"the node starts with the encrypted wallet.")


def cmd_decrypt(args):
    pw = _read_keyfile(args.keyfile)
    with open(args.wallet) as f:
        blob = json.load(f)
    pt = decrypt_bytes(blob, pw)
    data = json.loads(pt.decode())
    tmp = args.wallet + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    _chmod600(tmp)
    os.replace(tmp, args.wallet)
    print(f"decrypted {args.wallet} back to plaintext.")


def main():
    ap = argparse.ArgumentParser(description="Excalibur wallet encryption")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkeyfile")
    g.add_argument("--keyfile", required=True)
    g.add_argument("--force", action="store_true")
    g.set_defaults(fn=cmd_genkeyfile)
    e = sub.add_parser("encrypt")
    e.add_argument("--wallet", required=True)
    e.add_argument("--keyfile", required=True)
    e.add_argument("--force", action="store_true")
    e.set_defaults(fn=cmd_encrypt)
    d = sub.add_parser("decrypt")
    d.add_argument("--wallet", required=True)
    d.add_argument("--keyfile", required=True)
    d.set_defaults(fn=cmd_decrypt)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
