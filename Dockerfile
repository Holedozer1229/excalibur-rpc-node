FROM python:3.11-slim

LABEL org.excalibur.version="0.2.0"

WORKDIR /app

# Node modules (pure stdlib Python — no pip dependencies)
COPY excalibur.py genesis_fork.py txscript.py mempool.py chainstate.py \
     p2p.py node_rpc.py secp256k1.py utxodb.py caduceus.py \
     wallet_crypto.py bridge.py bip322.py ./
COPY systemd/ ./systemd/

# Excalibur mainnet: RPC on 9332, P2P on 9333
EXPOSE 9332 9333

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 -c "import json,urllib.request; \
    d=json.load(urllib.request.urlopen('http://127.0.0.1:9332/')); \
    assert d.get('ok'), 'node not healthy'"

# Ancillary RPC node: serves mainnet P2P/RPC without mining.
# For a mining node, drop --no-mine (see README).
CMD ["python3", "excalibur.py", "--network", "mainnet", \
     "--no-mine", "--rpc-host", "0.0.0.0", "--p2p-host", "0.0.0.0"]
