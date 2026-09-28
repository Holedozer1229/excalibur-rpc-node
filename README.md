# Excalibur Node Software — v0.2.0

Full node, miner, and JSON-RPC server for the Excalibur chain.
Pure-stdlib Python 3.11+ — no pip dependencies, no build step.

**Denominations:** whole coins are **EXCAL** (tEXCAL on testnet);
the smallest unit is the **sword** — 1 EXCAL = 100,000,000 swords.

## Quickstart

```bash
# Serve-only node (no mining) on mainnet
python3 excalibur.py --network mainnet --no-mine

# Solo miner on testnet (mines to your own wallet)
python3 excalibur.py --network testnet --workers 2

# Query it
curl -s -X POST http://127.0.0.1:19332/ \
  -d '{"method":"getblockcount","params":[],"id":1}'
```

## Networks and ports

| Network  | Ticker | RPC   | P2P   | Notes                                  |
|----------|--------|-------|-------|----------------------------------------|
| mainnet  | EXCAL  | 9332  | 9333  | Live chain                             |
| testnet  | tEXCAL | 19332 | 19333 | Fast blocks for development            |
| fork     | EXCAL  | 9432  | 9433  | BTC-tip fork chain                     |

## Docker

```bash
docker build -t excalibur-node:0.2.0 .
docker run -d -p 9332:9332 -p 9333:9333 excalibur-node:0.2.0
curl -s http://127.0.0.1:9332/   # {"ok": true, "height": ..., ...}
```

The image runs a serve-only mainnet node. To mine in Docker instead,
override the command, e.g.
`docker run ... excalibur-node:0.2.0 python3 excalibur.py --network mainnet --workers 2`.

## Render

Connect this repo — `render.yaml` is auto-detected and deploys the
serve-only mainnet node with `/` as the health-check path.

## CLI reference

```
--network mainnet|testnet|fork   chain to run (default: testnet)
--no-mine                        serve P2P/RPC without mining
--workers N                      parallel nonce-grinding processes
--pace SECS                      min seconds between blocks
--max-blocks N                   stop after N blocks (testing)
--tag TEXT                       coinbase tag (default: Excalibur)
--rpc-port PORT / --rpc-host ADDR
--p2p-port PORT / --p2p-host ADDR
--no-rpc                         disable the JSON-RPC server
--peer HOST:PORT                 bootstrap peer (repeatable)
--datadir DIR                    data directory (default: script dir)
--wallet-keyfile FILE            wallet passphrase file (or
                                 EXCALIBUR_WALLET_KEYFILE env)
--version                        print node version and exit
```

## JSON-RPC

POST JSON to the RPC port: `{"method": ..., "params": [...], "id": 1}`.

Methods: `getblockcount`, `getbestblockhash`, `getchaintips`,
`getblock`, `getrawmempool`, `getmempoolinfo`, `sendrawtransaction`,
`getnewaddress`, `getpkhaddress`, `getbalance`, `getutxos`,
`getpeerinfo`, `sendtoaddress`, `estimatesmartfee`,
`buildtunnelcapsule`, `validatetunnelcapsule`.

`GET /` returns `{"ok": true, "height": N, "hash": ...}` for health checks.

## The bridge (Command Deck API)

`bridge.py` exposes the node to the Excalibur Command Deck web console:

```bash
python3 bridge.py   # listens on 0.0.0.0:9443
```

On first run it prints a bearer token (saved once to
`~/.bridge_token`, mode 600). All calls need
`Authorization: Bearer <token>`.

## Data files

Created next to the script (or under `--datadir`):

- `chaindata*/` — chain state (JSONL, append-only, crash-safe)
- `wallet*.json` — node wallet (supports AES-256-CTR encryption
  via `wallet_crypto.py`)
- `mempool*.json`, `*.log`, `*.fees.json` — runtime files

These are git-ignored. Back up your wallet file.

## systemd

Ready-made units live in `systemd/` (`excalibur-mainnet`,
`excalibur-fork`, `excalibur-fork-peer`, `excalibur-bridge`).
They are the in-boot supervisor; pair with an external watchdog
for reboot recovery.

## Security notes

- The JSON-RPC server has **no authentication**. It binds
  `127.0.0.1` by default — keep it that way unless the port is
  firewalled or behind a reverse proxy.
- The bridge uses a bearer token (`~/.bridge_token`, mode 600).
  Never commit it, never share it.
- Wallet encryption (`wallet_crypto.py`) is AES-256-CTR with
  encrypt-then-HMAC-SHA256 and PBKDF2-HMAC-SHA256 (600k rounds).
  Keep the passphrase in a keyfile **outside** the data directory.

## What's in the box

| File              | Role                                              |
|-------------------|---------------------------------------------------|
| `excalibur.py`    | Node entry point: miner + P2P + RPC               |
| `genesis_fork.py` | Network params, genesis blocks, block validation  |
| `chainstate.py`   | Chain state, reorg logic, DAA                     |
| `txscript.py`     | Transactions, scripts, Lockbox (opcode-free) locks|
| `mempool.py`      | Mempool (no-RBF policy)                           |
| `p2p.py`          | Peer-to-peer networking                           |
| `node_rpc.py`     | JSON-RPC server                                   |
| `secp256k1.py`    | Pure-Python secp256k1                             |
| `utxodb.py`       | UTXO snapshot store                               |
| `caduceus.py`     | CADUCEUS tunnel-capsule checks (BIP-369 style)     |
| `wallet_crypto.py`| Wallet encryption tooling                         |
| `bridge.py`       | Bearer-token HTTP bridge for the web console      |
| `bip322.py`       | Message signing utilities                         |
| `claim_fork.py`, `migrate_pkh.py` | Chain utilities                        |
