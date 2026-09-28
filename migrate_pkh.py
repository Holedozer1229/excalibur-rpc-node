#!/usr/bin/env python3
"""Migrate wallet funds from legacy P2PK to PKH (Lockbox quantum-safe lock).

Builds, signs, and submits via RPC: N P2PK inputs -> 1 PKH output (fee 1000).
Does NOT mine; the node mines the block separately.
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from txscript import (p2pk_script, lock_pkh_for_pubkey, ser_tx, sign_input,
                      txid_display)
from chainstate import ChainState

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "chaindata_mainnet")
FEE = 1000  # base units, same as the '101 operation'


def rpc(method, params=[]):
    req = urllib.request.Request(
        "http://127.0.0.1:9332",
        data=json.dumps({"method": method, "params": params, "id": 1}).encode(),
        headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=15))["result"]


def main():
    w = json.load(open(os.path.join(HERE, "wallet_mainnet.json")))
    priv = int(w["priv"], 16)
    pub = bytes.fromhex(w["pub"])
    p2pk = p2pk_script(pub)
    pkh = lock_pkh_for_pubkey(pub)
    print("pkh lock:", pkh.hex())

    cs = ChainState(DATA_DIR, net="mainnet").load()
    print("tip:", cs.tip()["height"])
    inputs = []
    total = 0
    for (txid_b, vout), entries in cs.utxo.items():
        for (value, spk, is_cb, cb_h) in entries:
            if spk == p2pk:
                inputs.append((txid_b, vout, value))
                total += value
    if not inputs:
        print("NO P2PK UTXOs found - nothing to migrate")
        return
    print(f"found {len(inputs)} P2PK UTXO(s), total={total} ({total/1e8} EXCAL)")

    out_value = total - FEE
    assert out_value > 0, "fee exceeds balance"
    t = {"version": 1,
         "vin": [{"prev": txid_b, "idx": vout, "script": b"",
                  "seq": 0xffffffff} for txid_b, vout, _ in inputs],
         "vout": [{"value": out_value, "script": pkh}],
         "locktime": 0}
    for i in range(len(inputs)):
        t["vin"][i]["script"] = sign_input(t, i, p2pk, priv)
    raw = ser_tx(t)
    print("txid:", txid_display(raw))
    print("sending", out_value, "-> PKH, fee", FEE)
    txid = rpc("sendrawtransaction", [raw.hex()])
    print("mempool accepted:", txid)


if __name__ == "__main__":
    main()
