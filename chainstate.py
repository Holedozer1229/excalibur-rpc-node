"""chainstate.py — branched chain state for the Genesis Fork node.

Append-only JSONL block store (crash-safe, resumable). Every accepted block
— main-chain or side branch — is validated under fork consensus before it
lands. Tracks all tips by cumulative work; reorganizes when a side branch
overtakes the active chain.

Block hashes are internal byte order throughout.
"""
import json
import os
import time

from genesis_fork import (GENESIS, genesis_for, genesis_txs,
                          genesis_hash_for,
                          verify_genesis, use_network, NETWORKS,
                          ser_header, sha256d, txid, merkle_root,
                          bits_to_target, required_bits, subsidy,
                          check_coinbase_lineage, validate_block)
from txscript import (validate_block_txs, apply_block_txs, build_utxo,
                      utxo_stats)
from utxodb import UtxoSet, SnapshotDB, build_snapshot_db


def _fork_snapshot_paths(data_dir):
    here = os.path.dirname(os.path.abspath(__file__))
    snap_dir = os.path.join(here, "fork_balances")
    return {
        "dat": os.path.join(snap_dir, "snapshot_968698.dat"),
        "meta": os.path.join(snap_dir, "snapshot.json"),
        "db": os.path.join(data_dir, "utxo.db"),
    }


def _block_work(bits):
    return (1 << 256) // (bits_to_target(bits) + 1)


def _header_hash(rec):
    return sha256d(ser_header(rec["version"], rec["prev"], rec["merkle"],
                              rec["time"], rec["bits"], rec["nonce"]))


def _enc_rec(rec):
    return {"height": rec["height"], "version": rec["version"],
            "prev": rec["prev"].hex(), "merkle": rec["merkle"].hex(),
            "time": rec["time"], "bits": rec["bits"], "nonce": rec["nonce"],
            "hash": rec["hash"].hex(),
            "txs": [t.hex() for t in rec["txs"]]}


def _dec_rec(d):
    return {"height": d["height"], "version": d["version"],
            "prev": bytes.fromhex(d["prev"]),
            "merkle": bytes.fromhex(d["merkle"]),
            "time": d["time"], "bits": d["bits"], "nonce": d["nonce"],
            "hash": bytes.fromhex(d["hash"]),
            "txs": [bytes.fromhex(t) for t in d["txs"]]}


class ChainState:
    def __init__(self, data_dir, net="testnet"):
        self.data_dir = data_dir
        self.net = net
        self.params = NETWORKS[net]
        self.chain_path = os.path.join(data_dir, "chain.jsonl")
        self.index = {}      # hash bytes -> record
        self.children = {}   # hash bytes -> [child hash bytes]
        self.tips = []       # [{"height","hash","work"}] by work desc
        self.utxo = None     # UtxoSet; built in load()
        self._snapshot = None  # SnapshotDB (fork net only)
        # COMPAT SHIM (2026-09-26, Bodhi): another builder is mid-flight on
        # fork_balances/ (snapshot not built yet) and made the snapshot a
        # hard startup requirement, which crash-loops the node. Until the
        # snapshot exists the node runs on fork blocks alone — the behavior
        # every block so far was validated under. When the snapshot lands,
        # a restart picks it up via the normal path below.
        self._snapshot_unavailable = False
        self._tip_hash = None
        self._active_work = 0

    # ---------------------------------------------------------------- load
    def load(self):
        use_network(self.net)
        os.makedirs(self.data_dir, exist_ok=True)
        if os.path.exists(self.chain_path):
            records = self._load_records_tolerant()
        else:
            records = self._migrate_legacy()
        if not records:
            records = [self._genesis_record()]
            with open(self.chain_path, "w") as f:
                f.write(json.dumps(_enc_rec(records[0])) + "\n")
        for rec in records:
            self._index_record(rec)
        self._select_best_tip()
        self._replay_active()
        return self

    def _load_records_tolerant(self):
        """Read chain.jsonl, stopping at the first undecodable line.

        A truncated/corrupt tail (e.g. from a crash mid-append) is dropped
        and the file is truncated back to the last good record, instead of
        crashing the load. Only parsing is affected — every successfully
        decoded record loads exactly as before, so validation outcomes are
        unchanged.
        """
        records = []
        good_upto = 0
        dropped = 0
        with open(self.chain_path, "rb") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                if not line.strip():
                    good_upto = f.tell()
                    continue
                try:
                    rec = _dec_rec(json.loads(line.decode("utf-8")))
                except (json.JSONDecodeError, UnicodeDecodeError,
                        ValueError, KeyError, TypeError):
                    dropped += 1
                    break  # stop at first bad line: drop the tail
                records.append(rec)
                good_upto = f.tell()
        if dropped:
            # Truncate the corrupt tail so later appends land cleanly and
            # the next load sees the same prefix.
            with open(self.chain_path, "r+b") as f:
                f.truncate(good_upto)
        return records

    def _genesis_record(self):
        g = genesis_for(self.net)
        h = verify_genesis(self.net)
        return {"height": 0, "version": g["version"], "prev": g["prev"],
                "merkle": g["merkle"], "time": g["time"], "bits": g["bits"],
                "nonce": g["nonce"], "hash": h, "txs": genesis_txs(self.net)}

    def _migrate_legacy(self):
        """Best-effort import of the old linear testnet_live.jsonl."""
        if self.net != "testnet":
            return []
        here = os.path.dirname(os.path.abspath(__file__))
        legacy = os.path.join(here, "testnet_live.jsonl")
        if not os.path.exists(legacy):
            return []
        records = []
        with open(legacy) as f:
            for i, line in enumerate(f):
                d = json.loads(line)
                rec = {"height": i, "version": d["version"],
                       "prev": bytes.fromhex(d["prev"]),
                       "merkle": bytes.fromhex(d["merkle"]),
                       "time": d["time"], "bits": d["bits"],
                       "nonce": d["nonce"],
                       "hash": bytes.fromhex(d["hash"]),
                       "txs": [bytes.fromhex(t) for t in d["txs"]]}
                records.append(rec)
        with open(self.chain_path, "w") as f:
            for rec in records:
                f.write(json.dumps(_enc_rec(rec)) + "\n")
        return records

    # -------------------------------------------------------------- index
    def _index_record(self, rec):
        h = rec["hash"]
        self.index[h] = rec
        self.children.setdefault(h, [])
        self.children.setdefault(rec["prev"], []).append(h)
        rec["work"] = self.index.get(rec["prev"], {}).get("work", 0) \
            + _block_work(rec["bits"])

    def _path_to(self, tip_hash):
        """Records from genesis to tip_hash (inclusive), genesis-first."""
        path = []
        h = tip_hash
        while True:
            rec = self.index[h]
            path.append(rec)
            if rec["height"] == 0:
                break
            h = rec["prev"]
        path.reverse()
        return path

    def _select_best_tip(self):
        best, best_work = None, -1
        for h, rec in self.index.items():
            if not self.children.get(h) and rec["work"] > best_work:
                best, best_work = h, rec["work"]
        self._tip_hash = best
        self._active_work = best_work
        tips = [{"height": rec["height"], "hash": h.hex(),
                 "work": rec["work"]}
                for h, rec in self.index.items() if not self.children.get(h)]
        tips.sort(key=lambda t: -t["work"])
        self.tips = tips

    def _open_snapshot(self):
        """Open (building if needed) the fork's Bitcoin UTXO snapshot.

        Returns None when no snapshot has been built yet (see the compat
        shim in __init__): the node then runs on fork blocks alone.
        """
        p = _fork_snapshot_paths(self.data_dir)
        if not os.path.exists(p["meta"]):
            print("snapshot: fork_balances/snapshot.json not built yet — "
                  "running on fork blocks only", flush=True)
            return None
        with open(p["meta"]) as f:
            meta = json.load(f)
        if not os.path.exists(p["db"]):
            build_snapshot_db(p["dat"], p["db"], meta["sha256d"],
                              meta["height"], log=print)
        db = SnapshotDB(p["db"])
        if db.get_meta("snapshot_hash") != meta["sha256d"]:
            db.close()
            raise RuntimeError("snapshot DB hash mismatch: delete utxo.db "
                               "and rebuild")
        return db

    def _replay_active(self):
        # Fork net: the height-0 state is the Bitcoin snapshot (the genesis
        # record itself carries no txs); other nets start empty.
        base = None
        if self.net == "fork":
            if self._snapshot is None and not self._snapshot_unavailable:
                self._snapshot = self._open_snapshot()
                if self._snapshot is None:
                    self._snapshot_unavailable = True
            if self._snapshot is not None:
                base = UtxoSet(snapshot=self._snapshot)
        path = self._path_to(self._tip_hash)
        self.utxo = build_utxo([{"txs": rec["txs"]} for rec in path],
                               base=base)

    # -------------------------------------------------------------- views
    def tip(self):
        rec = self.index[self._tip_hash]
        return {"height": rec["height"], "hash": self._tip_hash.hex()}

    def _bits_context(self, prev_hash, height):
        """Ancestor {height: {"time","bits"}} for required_bits."""
        ctx = {}
        h = prev_hash
        for _ in range(self.params["retarget_interval"]):
            rec = self.index.get(h)
            if rec is None:
                break
            ctx[rec["height"]] = {"time": rec["time"], "bits": rec["bits"]}
            if rec["height"] == 0:
                break
            h = rec["prev"]
        return ctx

    def _fork_utxo(self, prev_hash):
        """UTXO set as of the block prev_hash. Tip case is a cheap copy
        (the snapshot is shared); side branches replay fork blocks over a
        fresh overlay (fork history is short)."""
        if prev_hash == self._tip_hash:
            return self.utxo.copy()
        base = None
        if self.net == "fork":
            if self._snapshot is None and not self._snapshot_unavailable:
                self._snapshot = self._open_snapshot()
                if self._snapshot is None:
                    self._snapshot_unavailable = True
            if self._snapshot is not None:
                base = UtxoSet(snapshot=self._snapshot)
        path = self._path_to(prev_hash)
        return build_utxo([{"txs": rec["txs"]} for rec in path], base=base)

    # -------------------------------------------------------------- submit
    def submit_block(self, blk):
        """Validate and store a block. Returns {"accepted": bool,
        "event": {...}|None, "reason": str}."""
        use_network(self.net)
        try:
            prev_hash = bytes(blk["prev"])
            txs = [bytes(t) for t in blk["txs"]]
        except Exception:
            return {"accepted": False, "event": None,
                    "reason": "malformed block fields"}
        prev = self.index.get(prev_hash)
        if prev is None:
            return {"accepted": False, "event": None,
                    "reason": "orphan: unknown prev"}
        height = prev["height"] + 1
        norm = {"version": blk["version"], "prev": prev_hash,
                "merkle": bytes(blk["merkle"]), "time": blk["time"],
                "bits": blk["bits"], "nonce": blk["nonce"], "txs": txs}
        hh = _header_hash(norm)
        if hh in self.index:
            # Already known (e.g. block arrived via both inv->getblock and
            # a broadcast push). Reject cleanly instead of re-appending a
            # duplicate record to the chain file.
            return {"accepted": False, "event": None,
                    "reason": "duplicate block"}
        fork_utxo = self._fork_utxo(prev_hash)
        path = self._path_to(prev_hash)
        bad = validate_block(norm, prev, height, path, utxo=fork_utxo)
        if bad:
            return {"accepted": False, "event": None, "reason": bad}
        rec = dict(norm, height=height, hash=hh, txs=txs)
        # append first: crash-safe, the record is fully validated
        with open(self.chain_path, "a") as f:
            f.write(json.dumps(_enc_rec(rec)) + "\n")
        self._index_record(rec)
        new_work = rec["work"]
        if new_work > self._active_work:
            # new best chain: reorg (or plain extension)
            old_path = self._path_to(self._tip_hash)
            new_path = self._path_to(hh)
            fork = 0
            while (fork < len(old_path) and fork < len(new_path)
                   and old_path[fork]["hash"] == new_path[fork]["hash"]):
                fork += 1
            removed = old_path[fork:]
            added = new_path[fork:]
            # Deep-reorg guard (small-chain 51% protection): refuse to unwind
            # more than max_reorg_depth blocks for a heavier branch — unless
            # our own tip is stale, in which case we are catching up after
            # downtime, not under attack.
            max_depth = self.params.get("max_reorg_depth", 0)
            if max_depth and len(removed) > max_depth:
                spacing = self.params.get("daa_spacing",
                                          self.params["target_spacing"])
                tip_time = old_path[-1]["time"] if old_path else 0
                stale = tip_time < time.time() - 2 * max_depth * spacing
                if not stale:
                    return {"accepted": False, "event": None,
                            "reason": "reorg too deep"}
            # fork_utxo is already a private UtxoSet (tip copy or fresh
            # side-branch replay): apply the block onto it directly.
            apply_block_txs(txs, fork_utxo, height)
            self.utxo = fork_utxo
            self._tip_hash = hh
            self._active_work = new_work
            self._select_best_tip()
            event = {"height": height, "hash": hh.hex(),
                     "added": added, "removed": removed}
            return {"accepted": True, "event": event, "reason": "ok"}
        self._select_best_tip()
        return {"accepted": True, "event": None, "reason": "side branch"}
