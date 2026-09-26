FROM python:3.11-slim

WORKDIR /app

COPY *.py ./

# Excalibur node: RPC on 9332, P2P on 9333
EXPOSE 9332 9333

# Run as ancillary RPC node (serve-only, no mining, public RPC)
CMD ["python3", "excalibur.py", "--network", "mainnet", "--no-mine", "--rpc-host", "0.0.0.0", "--p2p-host", "0.0.0.0"]
