"""node_rpc.py — localhost JSON-RPC for the Genesis Fork node.

POST / with {"method":..., "params":[...], "id":...}.
Read methods plus sendrawtransaction and a minimal wallet.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import secp256k1 as secp
from genesis_fork import sha256d
from txscript import (parse_tx, txid_internal, p2pk_script, COINBASE_MATURITY,
                      lock_pkh_for_pubkey)
import caduceus


def load_wallet_key(wallet_path):
    """Load (or create) the node's wallet keypair. Returns
    (priv_bytes, pub_compressed_bytes). The same key funds the miner: blocks
    the node finds pay this key's PKH lock directly."""
    if os.path.exists(wallet_path):
        w = json.load(open(wallet_path))
        return bytes.fromhex(w["priv"]), bytes.fromhex(w["pub"])
    priv = int.from_bytes(os.urandom(32), "big") % (secp.N - 1) + 1
    pub = secp.compress(secp.priv_to_pub(priv))
    json.dump({"priv": f"{priv:064x}", "pub": pub.hex()},
              open(wallet_path, "w"))
    return priv.to_bytes(32, "big"), pub


class Node:
    def __init__(self, cs, mempool, lock, wallet_path, peermgr=None):
        self.cs = cs
        self.mempool = mempool
        self.lock = lock
        self.wallet_path = wallet_path
        self.peermgr = peermgr
        self._srv = None

    # ------------------------------------------------------------ wallet
    def _wallet_key(self):
        return load_wallet_key(self.wallet_path)

    # ------------------------------------------------------------ server
    def serve_thread(self, port, host="127.0.0.1"):
        node = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                try:
                    n = int(self.headers.get("Content-Length", 0))
                    req = json.loads(self.rfile.read(n) or b"{}")
                except Exception:
                    return self._reply({"error": "bad request",
                                        "id": None})
                method = req.get("method")
                params = req.get("params", [])
                rid = req.get("id")
                try:
                    result = node.dispatch(method, params)
                    self._reply({"result": result, "error": None,
                                 "id": rid})
                except Exception as e:
                    self._reply({"result": None, "error": str(e),
                                 "id": rid})

            def _reply(self, obj):
                raw = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._srv = HTTPServer((host, port), Handler)
        t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        t.start()
        return t

    def shutdown(self):
        if self._srv:
            self._srv.shutdown()

    # ------------------------------------------------------------ methods
    def dispatch(self, method, params):
        fn = {"getblockcount": self.rpc_getblockcount,
              "getbestblockhash": self.rpc_getbestblockhash,
              "getchaintips": self.rpc_getchaintips,
              "getblock": self.rpc_getblock,
              "getrawmempool": self.rpc_getrawmempool,
              "getmempoolinfo": self.rpc_getmempoolinfo,
              "sendrawtransaction": self.rpc_sendrawtransaction,
              "getnewaddress": self.rpc_getnewaddress,
              "getpkhaddress": self.rpc_getpkhaddress,
              "getbalance": self.rpc_getbalance,
              "getutxos": self.rpc_getutxos,
              "getpeerinfo": self.rpc_getpeerinfo,
              "buildtunnelcapsule": self.rpc_buildtunnelcapsule,
              "validatetunnelcapsule": self.rpc_validatetunnelcapsule,
              }.get(method)
        if fn is None:
            raise ValueError(f"unknown method: {method}")
        return fn(params)

    def rpc_getblockcount(self, _p):
        with self.lock:
            return self.cs.tip()["height"]

    def rpc_getbestblockhash(self, _p):
        with self.lock:
            return self.cs.tip()["hash"]

    def rpc_getchaintips(self, _p):
        with self.lock:
            return [{"height": t["height"], "hash": t["hash"],
                     "work": hex(t["work"])} for t in self.cs.tips]

    def rpc_getblock(self, p):
        h = bytes.fromhex(p[0])
        with self.lock:
            rec = self.cs.index.get(h)
            if rec is None:
                raise ValueError("block not found")
            tip = self.cs.tip()["height"]
            return {"hash": rec["hash"].hex(), "height": rec["height"],
                    "confirmations": tip - rec["height"] + 1,
                    "version": rec["version"], "prev": rec["prev"].hex(),
                    "merkle": rec["merkle"].hex(), "time": rec["time"],
                    "bits": hex(rec["bits"]), "nonce": rec["nonce"],
                    "tx": [txid_internal(t).hex() for t in rec["txs"]]}

    def rpc_getrawmempool(self, _p):
        with self.lock:
            return list(self.mempool.txs.keys())

    def rpc_getmempoolinfo(self, _p):
        with self.lock:
            size = sum(len(v) for v in self.mempool.txs.values())
            return {"size": len(self.mempool), "bytes": size}

    def rpc_sendrawtransaction(self, p):
        raw = bytes.fromhex(p[0])
        with self.lock:
            ok, reason = self.mempool.add(raw, self.cs.utxo,
                                          self.cs.tip()["height"] + 1)
        if not ok:
            raise ValueError(f"rejected: {reason}")
        if self.peermgr:
            self.peermgr.broadcast_tx(raw)
        return txid_internal(raw).hex()

    def rpc_getnewaddress(self, _p):
        _priv, pub = self._wallet_key()
        return pub.hex()

    def rpc_getpkhaddress(self, _p):
        """Opcode-free Lockbox address: the wallet's PKH lock (hex). This is
        the quantum-protected address format for post-activation outputs."""
        _priv, pub = self._wallet_key()
        return lock_pkh_for_pubkey(pub).hex()

    def rpc_getbalance(self, _p):
        _priv, pub = self._wallet_key()
        # Legacy P2PK outputs plus post-Lockbox PKH outputs. Targeted
        # lookups: the full UTXO set is far too large to scan.
        want = [p2pk_script(pub), lock_pkh_for_pubkey(pub)]
        mature = immature = 0
        with self.lock:
            height = self.cs.tip()["height"]
            for spk in want:
                for _key, (value, _s, is_cb, cb_h) in \
                        self.cs.utxo.find_by_spk(spk):
                    if is_cb and height + 1 - cb_h < COINBASE_MATURITY:
                        immature += value
                    else:
                        mature += value
        return {"balance": mature / 1e8, "immature": immature / 1e8}

    def rpc_getutxos(self, p):
        """List UTXOs paying to a lock script. params: [script_hex].
        Returns [{txid (wire-order hex, as vin prev expects), vout, value
        (swords), mature, coinbase}]. Powers wallet UIs: keys stay client
        side; the UI builds + signs spends and submits via
        sendrawtransaction."""
        spk = bytes.fromhex(p[0])
        out = []
        with self.lock:
            height = self.cs.tip()["height"]
            for (txid_b, vout), (value, _s, is_cb, cb_h) in \
                    self.cs.utxo.find_by_spk(spk):
                mature = not (is_cb and height + 1 - cb_h < COINBASE_MATURITY)
                out.append({"txid": txid_b.hex(), "vout": vout,
                            "value": value, "mature": mature,
                            "coinbase": bool(is_cb)})
        return out

    def rpc_getpeerinfo(self, _p):
        if not self.peermgr:
            return []
        return [{"addr": f"{a[0]}:{a[1]}"} for _s, a in self.peermgr.peers]

    # ------------------------------------------- BIP-369 CADUCEUS capsules
    def rpc_buildtunnelcapsule(self, p):
        """Build a BIP-369 tunnel capsule. params[0] is an object with the
        build_capsule fields (state_type, index, proper_time_fs, direction,
        wormhole_pulse_id, source, destination, relayer, canonical_label,
        entanglement_chain_labels, bip322_sig, bip143_sig, qr_sig)."""
        if not p or not isinstance(p[0], dict):
            raise ValueError("buildtunnelcapsule needs one object param")
        try:
            return caduceus.build_capsule(**p[0])
        except TypeError as e:
            raise ValueError(f"bad capsule params: {e}")

    def rpc_validatetunnelcapsule(self, p):
        """Validate a BIP-369 tunnel capsule against the four Canons.
        BIP-143-style labels are checked against the live UTXO set."""
        if not p or not isinstance(p[0], dict):
            raise ValueError("validatetunnelcapsule needs one object param")
        with self.lock:
            ok, reasons = caduceus.validate_capsule(p[0], self.cs)
        return {"valid": ok, "reasons": reasons,
                "digest": caduceus.capsule_digest(p[0]) if ok else None}
