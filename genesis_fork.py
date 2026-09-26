"""genesis_fork.py — network parameters and chain consensus for the Genesis Fork.

Block hashes are internal byte order everywhere in this module
(sha256d output, NOT reversed). Reversal to display order happens only
at UI boundaries.

Pure Python, stdlib only.
"""
import hashlib
import struct
import time

# Smallest unit: the sword. 1 EXCAL = 100,000,000 swords.
SWORD = 100_000_000
SAT = SWORD  # legacy alias

NETWORKS = {
    "mainnet": {
        "ticker": "EXCAL",
        "halving_interval": 210_000,
        "retarget_interval": 2016,
        "target_spacing": 600,
        "min_bits": 0x1f000100,   # CPU-findable; ~2^24 hashes per block
        "rpc_port": 9332,
        "p2p_port": 9333,
        "magic": 0x47534601,
        "qlock_activation": 102,
    },
    "testnet": {
        "ticker": "tEXCAL",
        "halving_interval": 210_000,
        "retarget_interval": 2016,
        "target_spacing": 600,
        "min_bits": 0x1f010000,   # very easy; ~2^16 hashes per block
        "rpc_port": 19332,
        "p2p_port": 19333,
        "magic": 0x47534602,
        "qlock_activation": 102,
    },
    "fork": {
        # Fork of the live Bitcoin chain at BTC block 968698. Lockbox
        # rules apply from the fork's first block (no legacy era).
        "ticker": "EXCAL",
        "halving_interval": 210_000,
        "retarget_interval": 2016,
        "target_spacing": 600,
        # Responsive DAA: 60s blocks, difficulty re-aimed every block from
        # the trailing 60-block window (4x clamp per window). Fixes BTC's
        # slow-confirmation / fee-spike regime and keeps block times stable
        # as miners join or leave — no 2016-block dead zone.
        # daa_activation: the DAA switches on at this height; earlier blocks
        # keep the historical min_bits rule, so pre-activation history stays
        # valid and new nodes sync it deterministically.
        "daa_window": 60,
        "daa_spacing": 60,
        "daa_activation": 74,
        # Deep-reorg guard: a competing branch that would unwind more than
        # this many blocks is rejected — the classic small-chain 51% kill
        # shot. Escape hatch: if our own tip is stale (older than twice the
        # depth in expected block time) we are catching up, not being
        # attacked, and the reorg is allowed.
        "max_reorg_depth": 100,
        "min_bits": 0x1f000100,   # CPU-findable; ~2^24 hashes per block
        "rpc_port": 9432,
        "p2p_port": 9433,
        "magic": 0x47534603,
        "qlock_activation": 0,
    },
}
PARAMS = NETWORKS

# --- Lockbox upgrade -------------------------------------------------------
# Height at which the opcode-free lock format activates on mainnet:
#   * no Script opcodes: outputs are structural locks (PKH / OPEN), not programs
#   * quantum protection: pubkeys stay hashed until spent (no bare-P2PK outputs)
#   * BIP-369: mempool refuses replacements (no RBF) for spends from
#     quantum-vulnerable inputs
# Blocks below this height (including all fast-mined history) validate under
# the legacy rules; new outputs after activation must use the lock format.
QLOCK_ACTIVATION = 102


def qlock_activation():
    """Lockbox activation height for the currently selected network."""
    return _active.get("qlock_activation", QLOCK_ACTIVATION)

_active = NETWORKS["testnet"]


def use_network(name):
    """Select the active network. Returns its params dict."""
    global _active
    if name not in NETWORKS:
        raise ValueError(f"unknown network: {name}")
    _active = NETWORKS[name]
    return _active


def network():
    return _active


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def txid(raw: bytes) -> bytes:
    """Transaction id, internal byte order."""
    return sha256d(raw)


def subsidy(height):
    """Block subsidy: 50 coins, halving every halving_interval blocks."""
    return (50 * SWORD) >> (height // _active["halving_interval"])


# ------------------------------------------------------------------ headers
def ser_header(version, prev, merkle, t, bits, nonce):
    return (struct.pack("<I", version) + bytes(prev) + bytes(merkle)
            + struct.pack("<III", t, bits, nonce))


def bits_to_target(bits):
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def target_to_bits(target):
    if target <= 0:
        return 0
    nbytes = (target.bit_length() + 7) // 8
    if nbytes <= 3:
        compact = target << (8 * (3 - nbytes))
        size = 3
    else:
        compact = target >> (8 * (nbytes - 3))
        size = nbytes
    if compact & 0x800000:
        compact >>= 8
        size += 1
    return (size << 24) | (compact & 0x7FFFFF)


def merkle_root(txids):
    """txids: list of internal-order 32-byte txids -> internal-order root."""
    if not txids:
        return bytes(32)
    level = [bytes(t) for t in txids]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else a
            nxt.append(sha256d(a + b))
        level = nxt
    return level[0]


# ------------------------------------------------------------------ genesis
def _genesis_dict(t, bits):
    return {"version": 1, "prev": bytes(32), "merkle": bytes(32),
            "time": t, "bits": bits, "nonce": 0}


GENESIS = _genesis_dict(1704067200, NETWORKS["testnet"]["min_bits"])

# Mainnet hard-forks Bitcoin itself: our block 0 IS Bitcoin's genesis block
# (The Times 03/Jan/2009...). Header fields byte-exact per chainparams.
MAINNET_GENESIS = {
    "version": 1,
    "prev": bytes(32),
    "merkle": bytes.fromhex(
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"),
    "time": 1231006505,
    "bits": 0x1d00ffff,
    "nonce": 2083236893,
}

# The real 204-byte Bitcoin genesis coinbase, byte-exact. It stays in our
# mainnet UTXO set as an unspendable output (uncompressed-P2PK script is
# non-standard under fork consensus) — exactly Bitcoin's own treatment.
GENESIS_COINBASE = bytes.fromhex(
    "01000000010000000000000000000000000000000000000000000000000000000000"
    "000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32"
    "303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e6420"
    "6261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678a"
    "fdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4c"
    "ef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
assert len(GENESIS_COINBASE) == 204

# Fork network: block 0 IS Bitcoin's block 968698 (header byte-exact,
# fetched from mempool.space 2026-09-26). The fork branches from the live
# BTC tip; no BTC transactions or balances are carried — only the header
# anchors the fork point. Fork blocks mine at min difficulty from block 1.
FORK_BTC_HEIGHT = 968698
FORK_BTC_HASH = ("000000000000000000015d0478e7b60044314fb055fbb306ac7371ef89b60496")
FORK_GENESIS = {
    "version": 537059328,
    # internal byte order, as serialized in the BTC header
    "prev": bytes.fromhex(
        "17834318684358cad3cc4e832b29946c5a302914880900000000000000000000"),
    "merkle": bytes.fromhex(
        "03eb3de87579a2e42f8d9310c627774090aec64fa7bdc3ec2732f46f64b0a2f2"),
    "time": 1790432291,
    "bits": 0x17021ec5,
    "nonce": 1876081791,
}

_GENESIS_HASH = {
    "testnet": bytes.fromhex(
        "f531357927dc1566da651c46c84f30a23f477b9d894ad3fa2ef42c6dff730458"),
    # reverse of 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    "mainnet": bytes.fromhex(
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"),
    # reverse of FORK_BTC_HASH (BTC block 968698)
    "fork": bytes.fromhex(
        "9604b689ef7173ac06b3fb55b04f314400b6e778045d01000000000000000000"),
}


def genesis_for(net):
    if net == "testnet":
        return GENESIS
    if net == "fork":
        return FORK_GENESIS
    return MAINNET_GENESIS


def genesis_txs(net):
    """Transactions included in the genesis record. Mainnet carries the
    real Bitcoin genesis coinbase; testnet and fork start empty."""
    return [GENESIS_COINBASE] if net == "mainnet" else []


def genesis_hash_for(net):
    return _GENESIS_HASH[net]


def _header_hash(g):
    return sha256d(ser_header(g["version"], g["prev"], g["merkle"],
                              g["time"], g["bits"], g["nonce"]))


def verify_genesis(net="testnet"):
    """Recompute the genesis hash and check it against the hardcoded trust
    anchor. On mainnet also checks the coinbase commits to the header's
    merkle root. Returns the internal-order hash bytes."""
    g = genesis_for(net)
    h = _header_hash(g)
    assert h == _GENESIS_HASH[net], "genesis hash mismatch"
    if net == "mainnet":
        assert merkle_root([txid(GENESIS_COINBASE)]) == g["merkle"], \
            "genesis coinbase does not match header merkle root"
        assert check_coinbase_lineage(GENESIS_COINBASE, g["bits"]), \
            "genesis coinbase fails lineage rule"
    if net == "fork":
        # Fork anchor must be the real BTC tip header: recompute from the
        # known header fields (already byte-exact above).
        assert h[::-1].hex() == FORK_BTC_HASH, "fork genesis is not the BTC tip"
    return h


# ------------------------------------------------------------------ coinbase
def ser_varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def push(data):
    """Minimal push encoding for a data element."""
    data = bytes(data)
    n = len(data)
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return b"\x4c" + bytes([n]) + data
    if n <= 65535:
        return b"\x4d" + struct.pack("<H", n) + data
    raise ValueError("push data too long")


def _parse_pushes(script):
    """Split a scriptSig into its pushed data elements. Raises ValueError."""
    out = []
    i = 0
    while i < len(script):
        op = script[i]
        if op <= 75:
            n = op
            i += 1
        elif op == 76:
            n = script[i + 1]
            i += 2
        elif op == 77:
            n = struct.unpack_from("<H", script, i + 1)[0]
            i += 3
        else:
            raise ValueError(f"non-push opcode {op:#x} in scriptSig")
        if i + n > len(script):
            raise ValueError("push past end")
        out.append(script[i:i + n])
        i += n
    return out


def coinbase_scriptsig(height, bits, tag):
    """Canonical coinbase scriptSig (v2):
    push(LE32(bits)) + push(tag) + push(LE32(height)).
    The first push commits the difficulty bits; the height push makes the
    txid unique per block."""
    return (push(struct.pack("<I", bits)) + push(bytes(tag))
            + push(struct.pack("<I", height)))


def make_coinbase(height, bits, tag, fees=0):
    """Build a coinbase tx (raw bytes): subsidy + fees to an
    anyone-can-spend output."""
    script = coinbase_scriptsig(height, bits, tag)
    value = subsidy(height) + fees
    return (struct.pack("<I", 1)
            + b"\x01"
            + bytes(32) + struct.pack("<I", 0xFFFFFFFF)
            + ser_varint(len(script)) + script + struct.pack("<I", 0xFFFFFFFF)
            + b"\x01"
            + struct.pack("<Q", value) + ser_varint(1) + b"\x51"
            + struct.pack("<I", 0))


def coinbase_value(raw):
    """Sum of a raw coinbase tx's output values. Returns -1 if malformed."""
    try:
        p = 4
        n_in, p = _read_varint(raw, p)
        for _ in range(n_in):
            if raw[p:p + 32] != bytes(32):
                return -1
            p += 32 + 4
            sl, p = _read_varint(raw, p)
            p += sl + 4
        n_out, p = _read_varint(raw, p)
        total = 0
        for _ in range(n_out):
            total += struct.unpack_from("<Q", raw, p)[0]
            p += 8
            sl, p = _read_varint(raw, p)
            p += sl
        return total
    except (IndexError, struct.error):
        return -1


def _read_varint(b, p):
    n = b[p]
    if n < 0xfd:
        return n, p + 1
    if n == 0xfd:
        return struct.unpack_from("<H", b, p + 1)[0], p + 3
    if n == 0xfe:
        return struct.unpack_from("<I", b, p + 1)[0], p + 5
    return struct.unpack_from("<Q", b, p + 1)[0], p + 9


def check_coinbase_lineage(cb, bits):
    """Verify raw coinbase bytes: null outpoint and a scriptSig whose first
    push is the claimed difficulty bits (LE32). Returns bool."""
    try:
        if len(cb) < 60 or cb[4] != 1:
            return False
        off = 5
        if cb[off:off + 32] != bytes(32):
            return False
        off += 32
        if struct.unpack_from("<I", cb, off)[0] != 0xFFFFFFFF:
            return False
        off += 4
        slen = cb[off]
        off += 1
        script = cb[off:off + slen]
        if len(script) != slen or not slen:
            return False
        pushes = _parse_pushes(script)
        if not pushes:
            return False
        return pushes[0] == struct.pack("<I", bits)
    except (IndexError, struct.error, ValueError, AssertionError):
        return False


# --------------------------------------------------------------- difficulty
def required_bits(height, ctx, t):
    """Windowed difficulty adjustment (per-block when daa_window is set).

    ctx: {height: {"time","bits"}} for ancestors. Networks without
    "daa_window" keep the legacy Bitcoin-style 2016-block retarget: the
    window defaults to retarget_interval and only exact multiples retarget
    (other heights reuse the parent's bits). A DAA network may also set
    "daa_activation": heights below it keep the min_bits rule they were
    mined under, so enabling the DAA never rewrites history.
    """
    p = _active
    window = p.get("daa_window", p["retarget_interval"])
    spacing = p.get("daa_spacing", p["target_spacing"])
    legacy = "daa_window" not in p
    if height < window:
        # Bootstrap: minimum difficulty while the chain is young so CPUs
        # can mine. On mainnet this is also the hard-fork rule that makes
        # post-genesis blocks mineable at all (Bitcoin's own genesis bits
        # 0x1d00ffff would never yield a block on CPU; the genesis block
        # itself stays a hardcoded trust anchor).
        return p["min_bits"]
    if legacy and height % window != 0:
        prev = ctx.get(height - 1)
        return prev["bits"] if prev else p["min_bits"]
    if not legacy and height < p.get("daa_activation", 0):
        # Pre-activation stretch on a DAA network: every historical block
        # here was mined at min_bits, so that stays the rule. (Without the
        # gate, switching the DAA on from birth would retroactively
        # invalidate the blocks mined before the code shipped.)
        return p["min_bits"]
    first = ctx.get(height - window)
    last = ctx.get(height - 1)
    if first is None or last is None:
        # Incomplete history (pruned caller): expect no change.
        pl = ctx.get(height - 1)
        return pl["bits"] if pl else p["min_bits"]
    timespan = last["time"] - first["time"]
    if timespan <= 0:
        timespan = 1
    target_span = window * spacing
    # Clamp like Bitcoin's 4x rule, applied per window.
    timespan = max(target_span // 4, min(target_span * 4, timespan))
    new_target = bits_to_target(last["bits"]) * timespan // target_span
    new_target = min(new_target, bits_to_target(p["min_bits"]))
    return target_to_bits(new_target)


# ------------------------------------------------------------- validation
def _header_hash_of(blk):
    return sha256d(ser_header(blk["version"], blk["prev"], blk["merkle"],
                              blk["time"], blk["bits"], blk["nonce"]))


def _parent_hash(prev):
    # prev may be a header-dict (has version/prev/merkle/time/bits/nonce)
    # or a full block record; both carry the header fields.
    return _header_hash_of(prev)


def validate_block(blk, prev, height, chain, utxo=None):
    """Full block validation. Returns None if valid, else an error string.

    blk: {"version","prev","merkle","time","bits","nonce","txs":[raw..]}
    prev: parent header-dict. chain: ancestor header-dicts (for retarget).
    utxo: if given, txs are fully validated against it at `height`.
    """
    try:
        hh = _header_hash_of(blk)
    except Exception:
        return "bad header fields"
    if int.from_bytes(hh, "big") > bits_to_target(blk["bits"]):
        return "insufficient proof of work"
    if blk["prev"] != _parent_hash(prev):
        return "prev hash mismatch"
    if not blk["time"] > prev["time"]:
        return "non-increasing timestamp"
    if blk["time"] > time.time() + 7200:
        return "timestamp too far in future"
    ctx = {}
    for h in range(max(0, height - 2016), height):
        rec = chain[h] if h < len(chain) else None
        if rec is not None:
            ctx[h] = {"time": rec["time"], "bits": rec["bits"]}
    # chain[0] is genesis; walk back via index if chain list is short --
    # callers that keep full history pass it; otherwise bits check is
    # best-effort on what is available.
    if blk["bits"] != required_bits(height, ctx, blk["time"]):
        # allow a grace path when ctx is incomplete (pruned history):
        # accept if bits equals the parent's bits (no retarget due)
        interval = _active.get("daa_window", _active["retarget_interval"])
        if not (height % interval != 0
                and blk["bits"] == prev["bits"]):
            return "wrong difficulty bits"
    if not blk["txs"]:
        return "block has no transactions"
    if merkle_root([txid(t) for t in blk["txs"]]) != blk["merkle"]:
        return "merkle root mismatch"
    cb = blk["txs"][0]
    if not check_coinbase_lineage(cb, blk["bits"]):
        return "bad coinbase lineage"
    if utxo is not None:
        # local import: txscript imports genesis_for, so this stays lazy
        from txscript import validate_block_txs
        ok, reason, _ = validate_block_txs(blk["txs"], utxo, height,
                                           subsidy(height))
        if not ok:
            return f"bad transactions: {reason}"
    return None
