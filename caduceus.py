"""caduceus.py — BIP-369 "CADUCEUS Cross-Chain State Tunnel" (application layer).

Implements the tunnel-capsule format and the four BIP-369 Canons from the
forum draft (bitcointalk.org topic 5582787.0, author "Big Dick Rick",
2026-05-12/13).

This is an APPLICATION-LAYER standard: it defines a JSON capsule format for
tunneling labeled state (e.g. 64-hexagram / EPR-like state indices) across
chains, anchored to BIP-143-style UTXO labels and BIP-322-style message
attestations, with optional BIP-361-style post-quantum signatures. It makes
NO consensus changes and needs no activation height — wallets, relayers, and
bridges validate capsules off-chain.

Honest scope notes (kept next to the code so they don't drift):
- The draft is self-published on a forum; it is not an assigned BIP in
  bitcoin/bips, and BIP numbers are not self-assignable. Treat "BIP-369"
  here as the draft's own label.
- Canon 1 (deterministic state mapping) is implemented as a pure-stdlib
  SHA-256 expansion: identical on every system by construction.
- Canon 4's post-quantum signature is ADVISORY per the draft. This module
  does not verify PQ signatures — no PQ scheme is defined here.
- The geometric/ER vocabulary ("wormhole-pulse", "Berry-phase",
  "time-declination") is carried as opaque metadata. This module enforces
  its INVARIANCE across tunneling (Canon 3); it asserts no physics.
"""

import copy
import hashlib
import json
import math
import os
import re

# State families from the draft: name -> state-vector dimension.
FAMILIES = {
    "hexagram_64d": 64,
    "epr_128d": 128,
    "caduceus_256d": 256,
}

_VERSION = "1"
_BIP = "369"

# Canonical-label / entanglement-label shapes from the draft's examples:
#   canonical_label:             "bip-322_genesis:{txid}:{vout}"
#   entanglement_chain_labels[]: "bip-143_segwit:{txid}:{vout}"
#                                "bip-322_attest:..."
_RE_322 = re.compile(r"^bip-322_[a-z0-9]+:.+$")
_RE_143 = re.compile(r"^bip-143_segwit:[0-9a-fA-F]{64}:[0-9]+$")


# --------------------------------------------------------------------------
# Canon 1 — deterministic state mapping.
# state_vector = f(state_type, index) must be deterministic and identical
# everywhere. Pure hashlib expansion: no floats-from-platform issues, no
# numpy, no randomness.
# --------------------------------------------------------------------------
def state_vector(state_type, index, params=None):
    """Deterministic dim-D state vector for (state_type, index).

    Expands SHA-256(seed || counter) into dim floats in [-1, 1], then
    L2-normalizes. Identical on every system by construction.
    """
    if state_type not in FAMILIES:
        raise ValueError(f"unknown state family: {state_type!r}")
    dim = FAMILIES[state_type]
    if not isinstance(index, int) or isinstance(index, bool):
        raise ValueError("index must be an integer")
    if not 0 <= index < dim:
        raise ValueError(f"index {index} out of range for {state_type} "
                         f"(dim {dim})")
    seed = hashlib.sha256(f"bip-369/{state_type}/{index}".encode()).digest()
    if params is not None:
        seed = hashlib.sha256(
            seed + json.dumps(params, sort_keys=True,
                              separators=(",", ":")).encode()).digest()
    out = []
    ctr = 0
    while len(out) < dim:
        block = hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        for i in range(0, 32, 8):
            u = int.from_bytes(block[i:i + 8], "big") / 2 ** 64  # [0, 1)
            out.append(u * 2.0 - 1.0)
            if len(out) == dim:
                break
        ctr += 1
    norm = math.sqrt(sum(x * x for x in out))
    return [x / norm for x in out]


def materialize(capsule):
    """Reconstruct the canonical state vector for a capsule (Canon 1)."""
    st = capsule["state"]
    return state_vector(st["type"], st["index"])


# --------------------------------------------------------------------------
# Capsule construction (§3.1 of the draft).
# --------------------------------------------------------------------------
def build_capsule(state_type="hexagram_64d", index=0, proper_time_fs=0,
                  direction=(0.0, 0.0, 0.0), wormhole_pulse_id=None,
                  source="excalibur_mainnet", destination="",
                  relayer="", canonical_label="",
                  entanglement_chain_labels=(),
                  bip322_sig="", bip143_sig=None, qr_sig=None):
    """Build a BIP-369 tunnel capsule dict per the draft's §3.1 format."""
    if state_type not in FAMILIES:
        raise ValueError(f"unknown state family: {state_type!r}")
    dim = FAMILIES[state_type]
    if not isinstance(index, int) or isinstance(index, bool) \
            or not 0 <= index < dim:
        raise ValueError(f"index {index} out of range for {state_type}")
    if wormhole_pulse_id is None:
        wormhole_pulse_id = "pulse_" + os.urandom(8).hex()
    d = list(direction)
    if len(d) != 3:
        raise ValueError("direction must be a 3-vector")
    return {
        "version": _VERSION,
        "bip": _BIP,
        "networks": {
            "source": source,
            "destination": destination,
            "relayer": relayer,
        },
        "state": {
            "type": state_type,
            "index": index,
            "canonical_label": canonical_label,
            "entanglement_chain_labels": list(entanglement_chain_labels),
            "geometric_meta": {
                "proper_time_fs": proper_time_fs,
                "direction": [float(x) for x in d],
                "wormhole_pulse_id": wormhole_pulse_id,
            },
        },
        "signatures": {
            "source_chain": bip322_sig,
            **({"relayer": bip143_sig} if bip143_sig is not None else {}),
            **({"post_quantum": qr_sig} if qr_sig is not None else {}),
        },
    }


def canonical_bytes(capsule):
    """Canonical JSON encoding (sorted keys, compact separators) for
    signing/digesting — the byte string a BIP-322-style source_chain
    attestation signs over."""
    return json.dumps(capsule, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def capsule_digest(capsule):
    """SHA-256 hex digest of the canonical encoding."""
    return hashlib.sha256(canonical_bytes(capsule)).hexdigest()


# --------------------------------------------------------------------------
# Validation — the four Canons (§3.2 of the draft).
# --------------------------------------------------------------------------
def _is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) \
        and math.isfinite(x)


def _parse_143_label(label):
    """Split a bip-143_segwit:{txid}:{vout} label. Returns (txid_bytes, vout)
    with txid in the byte order keying the UTXO set, or None."""
    m = _RE_143.match(label)
    if not m:
        return None
    parts = label.split(":")  # ["bip-143_segwit", txid_hex, vout]
    return bytes.fromhex(parts[1]), int(parts[2])


def validate_capsule(capsule, chain=None):
    """Validate a capsule against the BIP-369 Canons.

    chain: optional object with a `.utxo` dict keyed by
    (txid_bytes, vout) — used to check BIP-143-style labels against live
    UTXO state (§4.2 relay validation). Returns (ok, reasons).
    """
    reasons = []

    def bad(msg):
        reasons.append(msg)

    if not isinstance(capsule, dict):
        return False, ["capsule must be a JSON object"]
    if capsule.get("version") != _VERSION:
        bad(f"version must be {_VERSION!r}")
    if capsule.get("bip") != _BIP:
        bad(f"bip must be {_BIP!r}")

    nets = capsule.get("networks")
    if not isinstance(nets, dict):
        bad("networks must be an object")
    else:
        for f in ("source", "destination", "relayer"):
            v = nets.get(f)
            if not isinstance(v, str) or not v:
                bad(f"networks.{f} must be a non-empty string")

    st = capsule.get("state")
    if not isinstance(st, dict):
        bad("state must be an object")
        st = {}
    stype = st.get("type")
    if stype not in FAMILIES:
        bad(f"state.type must be one of {sorted(FAMILIES)}")
    idx = st.get("index")
    if not isinstance(idx, int) or isinstance(idx, bool) or \
            (stype in FAMILIES and not 0 <= idx < FAMILIES[stype]):
        bad("state.index out of range for its family")

    # Canon 2 — canonical attestation required: at least one BIP-143-style
    # or BIP-322-style label, each well-formed.
    cl = st.get("canonical_label")
    if not isinstance(cl, str) or not _RE_322.match(cl):
        bad("state.canonical_label must be a bip-322_* label")
    elabs = st.get("entanglement_chain_labels")
    if not isinstance(elabs, list) or not elabs:
        bad("state.entanglement_chain_labels must be a non-empty list")
        elabs = []
    for lab in elabs:
        if not isinstance(lab, str) or \
                not (_RE_143.match(lab) or _RE_322.match(lab)):
            bad(f"bad entanglement label: {lab!r}")

    # Canon 3 — ER-consistency: geometric_meta present and well-formed.
    # Invariance across tunneling is enforced by relay_emit/retunnel.
    gm = st.get("geometric_meta")
    if not isinstance(gm, dict):
        bad("state.geometric_meta must be an object")
        gm = {}
    pt = gm.get("proper_time_fs")
    if not isinstance(pt, int) or isinstance(pt, bool) or pt < 0:
        bad("geometric_meta.proper_time_fs must be a non-negative integer")
    direction = gm.get("direction")
    if not isinstance(direction, list) or len(direction) != 3 or \
            not all(_is_num(x) for x in direction):
        bad("geometric_meta.direction must be a 3-vector of finite numbers")
    if not isinstance(gm.get("wormhole_pulse_id"), str) or \
            not gm.get("wormhole_pulse_id"):
        bad("geometric_meta.wormhole_pulse_id must be a non-empty string")

    sigs = capsule.get("signatures")
    if not isinstance(sigs, dict):
        bad("signatures must be an object")
        sigs = {}
    if not isinstance(sigs.get("source_chain"), str) or \
            not sigs.get("source_chain"):
        bad("signatures.source_chain (BIP-322 attestation) is required")
    # Canon 4 — post_quantum is optional and advisory; presence only.
    pq = sigs.get("post_quantum")
    if pq is not None and (not isinstance(pq, str) or not pq):
        bad("signatures.post_quantum, if present, must be a non-empty string")

    # §4.2 relay validation: BIP-143 labels must reference live UTXOs.
    if chain is not None and not reasons:
        utxo = getattr(chain, "utxo", {})
        for lab in elabs:
            parsed = _parse_143_label(lab)
            if parsed is None:
                continue  # BIP-322-style labels need no UTXO lookup
            key = (parsed[0], parsed[1])
            if key not in utxo:
                bad(f"BIP-143 label references unknown UTXO: {lab!r}")

    ok = not reasons
    return ok, reasons


def _check_er_consistency(before_gm, after_gm):
    """Canon 3: the tunnel must not modify geometric_meta."""
    if before_gm != after_gm:
        raise ValueError(
            "Canon 3 violated: geometric_meta changed under tunneling")


# --------------------------------------------------------------------------
# Operation over chains (§4 of the draft): relay validation + emit on B.
# --------------------------------------------------------------------------
def relay_emit(capsule, chain=None):
    """Validate a capsule (§4.2) and emit the destination-chain state event
    (§4.3, mirroring the draft's StateTunneled Solidity event).

    Raises ValueError on any Canon violation. Returns the event dict.
    Canon 3 is enforced: geometric_meta is byte-identical before/after.
    """
    ok, reasons = validate_capsule(capsule, chain)
    if not ok:
        raise ValueError("capsule rejected: " + "; ".join(reasons))
    gm_before = copy.deepcopy(capsule["state"]["geometric_meta"])
    event = {
        "event": "StateTunneled",
        "sourceChainId": capsule["networks"]["source"],
        "destChainId": capsule["networks"]["destination"],
        "stateType": capsule["state"]["type"],
        "hexagramIndex": capsule["state"]["index"],
        "timeDeclinationFs": gm_before["proper_time_fs"],
        "directionVector": list(gm_before["direction"]),
        "wormholePulseId": gm_before["wormhole_pulse_id"],
        "canonicalLabel": capsule["state"]["canonical_label"],
        "capsuleDigest": capsule_digest(capsule),
    }
    gm_after = {"proper_time_fs": event["timeDeclinationFs"],
                "direction": event["directionVector"],
                "wormhole_pulse_id": event["wormholePulseId"]}
    _check_er_consistency(gm_before, gm_after)
    return event


def retunnel(capsule, new_destination):
    """Re-target a capsule at a new destination chain (§4.3 emit on B).

    Returns a copy with only networks.destination changed; Canon 3
    (geometric_meta invariance) is enforced.
    """
    new = copy.deepcopy(capsule)
    new["networks"]["destination"] = new_destination
    _check_er_consistency(capsule["state"]["geometric_meta"],
                          new["state"]["geometric_meta"])
    return new
