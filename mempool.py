"""mempool.py — unconfirmed transaction pool for the Genesis Fork node.

Persists to JSON; every tx is revalidated against the current UTXO set on
load and at template time. Pure Python, stdlib only.

BIP-369 (quantum protection): replace-by-fee is disabled. A transaction
that conflicts with one already in the mempool is rejected outright --
never considered as a replacement. Rationale: spends from
quantum-vulnerable locks (bare-P2PK, whose keys are exposed at rest, and
PKH, whose key is exposed in the mempool at spend time) give a quantum
adversary a short-exposure window to derive the key and RBF-steal the
funds. Refusing replacements closes that theft path; the first-seen
transaction keeps its head start and confirms first.
Excalibur goes one step further than BIP-369 strictly requires and
disables RBF entirely (there is no keyless input type worth replacing).
"""
import base64
import json
import os

from txscript import parse_tx, txid_internal, validate_tx, _view_copy


def _tx_inputs(raw):
    t = parse_tx(raw)
    return {(v["prev"], v["idx"]) for v in t["vin"]}


class Mempool:
    def __init__(self, path):
        self.path = path
        self.txs = {}  # txid hex (internal order) -> raw bytes
        self.spent = {}  # (prev_bytes, idx) -> txid hex spending it

    # ------------------------------------------------------------ persist
    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({k: base64.b64encode(v).decode() for k, v in
                       self.txs.items()}, f)
        os.replace(tmp, self.path)

    def _index(self, tid_hex, raw):
        for key in _tx_inputs(raw):
            self.spent[key] = tid_hex

    def _unindex(self, tid_hex, raw):
        for key in _tx_inputs(raw):
            if self.spent.get(key) == tid_hex:
                del self.spent[key]

    def load(self, utxo, height):
        """Reload persisted txs, keeping only ones still valid. Returns the
        number kept."""
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0
        kept = 0
        for tid_hex, b64 in data.items():
            try:
                raw = base64.b64decode(b64)
            except Exception:
                continue
            if txid_internal(raw).hex() != tid_hex:
                continue
            ok, _, _ = validate_tx(raw, utxo, height)
            if ok:
                self.txs[tid_hex] = raw
                self._index(tid_hex, raw)
                kept += 1
        return kept

    # -------------------------------------------------------------- ops
    def add(self, raw, utxo, height):
        """Try to admit a raw tx. Returns (ok, reason).

        BIP-369: conflicting transactions are never treated as replacements.
        If any input is already spent by a mempool tx, the newcomer is
        rejected outright -- no RBF, so a quantum adversary observing a
        key-revealing spend in the mempool cannot displace it.
        """
        raw = bytes(raw)
        try:
            t = parse_tx(raw)
        except Exception:
            return False, "parse failed"
        tid = txid_internal(raw).hex()
        if tid in self.txs:
            return False, "already in mempool"
        for v in t["vin"]:
            key = (v["prev"], v["idx"])
            if key in self.spent:
                return False, (
                    "conflicting tx already in mempool "
                    "(BIP-369: no replace-by-fee)")
        ok, reason, _ = validate_tx(raw, utxo, height)
        if not ok:
            return False, reason
        self.txs[tid] = raw
        self._index(tid, raw)
        self.save()
        return True, "ok"

    def remove(self, tid_hex):
        if tid_hex in self.txs:
            self._unindex(tid_hex, self.txs[tid_hex])
            del self.txs[tid_hex]
            self.save()

    def evict_block_txs(self, txs):
        """Drop txs confirmed by a new block (skip the coinbase)."""
        for raw in txs[1:]:
            self.remove(txid_internal(raw).hex())

    def select_template(self, utxo, height, max_txs=999):
        """Pick (raw, fee) pairs for the next block template: highest fee
        first, each validated against the utxo plus already-selected txs."""
        scored = []
        for raw in self.txs.values():
            ok, _, fee = validate_tx(raw, utxo, height)
            if ok:
                scored.append((fee, raw))
        scored.sort(key=lambda s: -s[0])
        overlay = _view_copy(utxo)
        template = []
        for _fee, raw in scored:
            if len(template) >= max_txs:
                break
            ok, _, fee = validate_tx(raw, utxo, height, view=overlay)
            if ok:
                template.append((raw, fee))
        return template

    def __len__(self):
        return len(self.txs)
