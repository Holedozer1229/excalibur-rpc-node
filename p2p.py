"""p2p.py — minimal localhost P2P for the Genesis Fork node.

Length-prefixed JSON messages over TCP:
  hello    {"t":"hello","magic":..,"height":..,"hash":hex,"port":listen_port}
  inv      {"t":"inv","hash":hex,"height":..}
  getblock {"t":"getblock","hash":hex}
  block    {"t":"block","block":{...}}
  tx       {"t":"tx","tx":hex}   (unconfirmed transaction relay)
  addr     {"t":"addr","addrs":["host:port",...]}  (peer gossip)

Every miner is a full node: blocks and transactions gossip peer-to-peer and
each node relays what it validates — no central server. Peer addresses
gossip too, so a bootstrap seed is only needed for first contact; once a
node knows one peer it discovers the rest and the seed can disappear.

On receiving a block the node validates it under fork consensus and relays
it. Orphans trigger a getblock for the missing parent (header-first lite
sync). All chainstate/mempool access goes through the shared lock.
"""
import json
import socket
import struct
import threading

from txscript import txid_internal


def _blk_to_json(blk):
    txs = [t.hex() if isinstance(t, (bytes, bytearray)) else t
           for t in blk["txs"]]
    prev = blk["prev"].hex() if isinstance(blk["prev"], (bytes, bytearray)) \
        else blk["prev"]
    merkle = blk["merkle"].hex() if isinstance(blk["merkle"],
                                               (bytes, bytearray)) \
        else blk["merkle"]
    return {"version": blk["version"], "prev": prev, "merkle": merkle,
            "time": blk["time"], "bits": blk["bits"], "nonce": blk["nonce"],
            "txs": txs}


def _blk_from_json(d):
    return {"version": d["version"], "prev": bytes.fromhex(d["prev"]),
            "merkle": bytes.fromhex(d["merkle"]), "time": d["time"],
            "bits": d["bits"], "nonce": d["nonce"],
            "txs": [bytes.fromhex(t) for t in d["txs"]]}


def _send(sock, msg):
    raw = json.dumps(msg).encode()
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def _fmt_addr(host, port):
    """host:port string, bracketing IPv6 literals."""
    host = host.strip()
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"
    return f"{host}:{port}"


def _parse_addr(s):
    """Inverse of _fmt_addr: 'host:port' or '[v6::lit]:port' -> (host, port)."""
    host, port = s.rsplit(":", 1)
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host, int(port)


def _recv_loop(sock):
    buf = b""
    while True:
        while len(buf) < 4:
            chunk = sock.recv(65536)
            if not chunk:
                return
            buf += chunk
        (n,) = struct.unpack(">I", buf[:4])
        while len(buf) - 4 < n:
            chunk = sock.recv(65536)
            if not chunk:
                return
            buf += chunk
        msg = json.loads(buf[4:4 + n].decode())
        buf = buf[4 + n:]
        yield msg


class PeerManager:
    def __init__(self, cs, mempool, lock, port=0, log=print,
                 host="127.0.0.1"):
        self.cs = cs
        self.mempool = mempool
        self.lock = lock
        self.port = port
        self.host = host
        self.log = log
        self.magic = cs.params["magic"]
        self.peers = []  # [(sock, addr)]
        self.known = set()  # "host:port" strings learned via gossip/bootstrap
        self._stop = threading.Event()
        self._srv = None

    # ------------------------------------------------------------------
    def start(self):
        bind_opts = []
        if self.host == "0.0.0.0":
            # one dual-stack socket serves v4 and v6; fall back to v4-only
            bind_opts = [(socket.AF_INET6, "::", 0),
                         (socket.AF_INET, "0.0.0.0", None)]
        else:
            fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            bind_opts = [(fam, self.host, None)]
        for fam, host, v6only in bind_opts:
            try:
                srv = socket.socket(fam, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if v6only is not None:
                    srv.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_V6ONLY, v6only)
                srv.bind((host, self.port))
                srv.listen(8)
                self._srv = srv
                break
            except OSError:
                continue
        if self._srv is None:
            raise OSError("p2p: cannot bind listen socket")
        self._srv.settimeout(0.5)
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._add_peer(conn, addr)

    def connect(self, host, port):
        last = None
        try:
            ais = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                     socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise OSError(f"cannot resolve {host}: {e}")
        for fam, st, _proto, _canon, sa in ais:
            try:
                s = socket.socket(fam, st)
                s.settimeout(10)
                s.connect(sa)
                s.settimeout(None)
                self.known.add(_fmt_addr(host, port))
                self._add_peer(s, (host, port))
                return
            except OSError as e:
                last = e
        raise last or OSError(f"cannot connect to {host}:{port}")

    def _dial_gossiped(self):
        """Dial a couple of gossiped addresses we aren't already on."""
        if self.peer_count() >= 12:
            return
        dialed = 0
        for a in sorted(self.known):
            if dialed >= 2 or self.peer_count() >= 12:
                break
            try:
                host, port = _parse_addr(a)
            except (ValueError, IndexError):
                continue
            if (port == self.port
                    and host in ("127.0.0.1", "::1", "localhost")):
                continue  # that's us
            if any(pa[0] == host and pa[1] == port for _s, pa in self.peers):
                continue
            try:
                self.connect(host, port)
                dialed += 1
            except OSError:
                continue

    def _add_peer(self, sock, addr):
        self.peers.append((sock, addr))
        t = threading.Thread(target=self._peer_loop, args=(sock, addr),
                             daemon=True)
        t.start()
        try:
            with self.lock:
                tip = self.cs.tip()
            _send(sock, {"t": "hello", "magic": self.magic,
                         "height": tip["height"], "hash": tip["hash"],
                         "port": self.port})
        except OSError:
            self._drop(sock)

    def _drop(self, sock):
        self.peers = [(s, a) for s, a in self.peers if s is not sock]
        try:
            sock.close()
        except OSError:
            pass

    def _peer_loop(self, sock, addr):
        try:
            for msg in _recv_loop(sock):
                try:
                    self._handle(sock, addr, msg)
                except Exception as e:
                    self.log(f"p2p: bad message from {addr}: {e}")
        except (OSError, json.JSONDecodeError, struct.error):
            pass
        finally:
            self._drop(sock)

    # ------------------------------------------------------------------
    def _handle(self, sock, addr, msg):
        t = msg.get("t")
        if t == "hello":
            if msg.get("magic") != self.magic:
                self.log(f"p2p: {addr} wrong magic, dropping")
                self._drop(sock)
                return
            # learn the sender's listen address for gossip (port 0 = not dialable)
            try:
                peer_host = addr[0]
                peer_port = int(msg.get("port", 0) or 0)
            except (ValueError, TypeError, IndexError):
                peer_host, peer_port = None, 0
            if peer_host and peer_port:
                self.known.add(_fmt_addr(peer_host, peer_port))
            with self.lock:
                tip = self.cs.tip()
            if msg.get("height", -1) > tip["height"]:
                _send(sock, {"t": "getblock", "hash": msg["hash"]})
            # answer first contact with our peer list: the seed is disposable
            try:
                _send(sock, {"t": "addr",
                             "addrs": sorted(self.known)[:20]})
            except OSError:
                pass
        elif t == "addr":
            for a in msg.get("addrs", [])[:20]:
                if isinstance(a, str) and a not in self.known:
                    self.known.add(a)
            threading.Thread(target=self._dial_gossiped, daemon=True).start()
        elif t == "getblock":
            h = bytes.fromhex(msg["hash"])
            with self.lock:
                rec = self.cs.index.get(h)
                payload = _blk_to_json(rec) if rec else None
            if payload:
                _send(sock, {"t": "block", "block": payload})
        elif t == "inv":
            h = bytes.fromhex(msg["hash"])
            with self.lock:
                known = h in self.cs.index
            if not known:
                _send(sock, {"t": "getblock", "hash": msg["hash"]})
        elif t == "block":
            blk = _blk_from_json(msg["block"])
            with self.lock:
                sub = self.cs.submit_block(blk)
                ev = sub.get("event")
                if sub["accepted"] and ev:
                    self._apply_reorg_side_effects(ev)
            if sub["accepted"]:
                self._relay(blk, exclude=sock)
            elif sub.get("reason", "").startswith("orphan"):
                _send(sock, {"t": "getblock",
                             "hash": blk["prev"].hex()})
        elif t == "tx":
            try:
                raw = bytes.fromhex(msg["tx"])
            except (ValueError, TypeError):
                return
            with self.lock:
                ok, _reason = self.mempool.add(
                    raw, self.cs.utxo, self.cs.tip()["height"] + 1)
            if ok:
                self._relay_tx(raw, exclude=sock)

    def _relay(self, blk, exclude=None):
        msg = {"t": "block", "block": _blk_to_json(blk)}
        for s, _ in list(self.peers):
            if s is exclude:
                continue
            try:
                _send(s, msg)
            except OSError:
                self._drop(s)

    def _relay_tx(self, raw, exclude=None):
        msg = {"t": "tx", "tx": bytes(raw).hex()}
        for s, _ in list(self.peers):
            if s is exclude:
                continue
            try:
                _send(s, msg)
            except OSError:
                self._drop(s)

    def broadcast_tx(self, raw):
        """Announce a new mempool transaction to all peers."""
        self._relay_tx(raw)

    def broadcast_block(self, blk):
        """Announce a newly mined block. Caller holds the lock."""
        inv = {"t": "inv", "hash": self._hash_of(blk),
               "height": self.cs.tip()["height"]}
        for s, _ in list(self.peers):
            try:
                _send(s, inv)
            except OSError:
                self._drop(s)
        # also push the full block: cheap on localhost, faster relay
        self._relay(blk)

    @staticmethod
    def _hash_of(blk):
        from genesis_fork import ser_header, sha256d
        return sha256d(ser_header(blk["version"], bytes(blk["prev"]),
                                  bytes(blk["merkle"]), blk["time"],
                                  blk["bits"], blk["nonce"])).hex()

    # ------------------------------------------------------------------
    def _apply_reorg_side_effects(self, ev):
        """Mempool fix-up after the active chain changes. Caller holds
        the lock."""
        for rec in ev.get("added", []):
            self.mempool.evict_block_txs(rec["txs"])
        if ev.get("removed"):
            with_height = self.cs.tip()["height"]
            for rec in ev["removed"]:
                for raw in rec["txs"][1:]:
                    try:
                        self.mempool.add(raw, self.cs.utxo, with_height)
                    except Exception:
                        pass

    def peer_count(self):
        return len(self.peers)

    def shutdown(self):
        self._stop.set()
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass
        for s, _ in list(self.peers):
            self._drop(s)
