#!/usr/bin/env python3
"""Claim matured OPEN (anyone-spend) fork coinbases to the wallet's PKH lock.

Anyone-spend inputs take an empty scriptSig. Fee 1000 base units total.
Submits via the fork RPC (9432); does NOT mine.
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from genesis_fork import use_network
use_network("fork")
from txscript import (lock_pkh_for_pubkey, lock_open, ser_tx, txid_display,
                      COINBASE_MATURITY)
from chainstate import ChainState

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "chaindata_fork")
FEE = 1000
RPC = "http://127.0.0.1:9432"


def rpc(method, params=[]):
    req = urllib.request.Request(
        RPC, data=json.dumps({"method": method, "params": params, "id": 1}).encode(),
        headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=15))["result"]


def main():
    w = json.load(open(os.path.join(HERE, "wallet_fork.json")))
    pub = bytes.fromhex(w["pub"])
    pkh = lock_pkh_for_pubkey(pub)
    print("pkh lock:", pkh.hex())

    cs = ChainState(DATA_DIR, net="fork").load()
    tip = cs.tip()["height"]
    print("tip:", tip)
    spend_h = tip + 1
    inputs, total = [], 0
    for (txid_b, vout), entries in cs.utxo.items():
        for (value, spk, is_cb, cb_h) in entries:
            if spk == lock_open() and is_cb and spend_h - cb_h >= COINBASE_MATURITY:
                inputs.append((txid_b, vout, value, cb_h))
                total += value
    if not inputs:
        print("no mature OPEN coinbases to claim")
        return
    inputs.sort(key=lambda x: x[3])
    print(f"claiming {len(inputs)} mature OPEN coinbase(s), total={total} ({total/1e8} EXCAL)")
    out_value = total - FEE
    assert out_value > 0
    t = {"version": 1,
         "vin": [{"prev": txid_b, "idx": vout, "script": b"",
                  "seq": 0xffffffff} for txid_b, vout, _, _ in inputs],
         "vout": [{"value": out_value, "script": pkh}],
         "locktime": 0}
    raw = ser_tx(t)
    print("txid:", txid_display(raw))
    print("claiming", out_value, "-> PKH, fee", FEE)
    print("mempool accepted:", rpc("sendrawtransaction", [raw.hex()]))


if __name__ == "__main__":
    main()
