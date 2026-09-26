"""utxodb.py — two-tier UTXO set for the fork: immutable Bitcoin snapshot + overlay.

The fork's UTXO set at height 0 is the entire Bitcoin UTXO set at BTC block
968698 (~10^8 outputs) — far too large for an in-memory dict. This module
provides:

  SnapshotDB  — read-only SQLite view of the imported snapshot. Built once
                from snapshot_968698.dat (hash-verified), then immutable.
  UtxoSet     — dict-compatible UTXO set: in-memory overlay (fork-created
                outputs) + tombstones (spent snapshot outputs) over a
                SnapshotDB. copy() is cheap (shares the snapshot).

Entry format everywhere is the legacy 4-tuple:
    (value_swords, lock_script_bytes, is_coinbase, cb_height)
so existing txscript/chainstate/mempool code works unchanged.
"""
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS utxo(
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    value INTEGER NOT NULL,
    spk BLOB NOT NULL,
    is_cb INTEGER NOT NULL,
    cb_h INTEGER NOT NULL,
    spendable INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_spk ON utxo(spk);
"""


class SnapshotDB:
    """Read-only handle on the imported Bitcoin UTXO snapshot."""

    def __init__(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"snapshot DB missing: {path}")
        self.path = path
        # read-only, immutable: shared cache, no locking needed
        self._db = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                                  check_same_thread=False)
        self._db.execute("PRAGMA query_only=ON")

    def close(self):
        self._db.close()

    def get(self, key):
        """key = (txid_bytes, vout) -> [(value, spk, is_cb, cb_h)] or None."""
        txid_b, vout = key
        row = self._db.execute(
            "SELECT value, spk, is_cb, cb_h FROM utxo WHERE txid=? AND vout=?",
            (txid_b, vout)).fetchone()
        if row is None:
            return None
        return [(row[0], bytes(row[1]), row[2], row[3])]

    def get_meta(self, k):
        row = self._db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else None

    def stats(self):
        n, total = self._db.execute(
            "SELECT COUNT(*), COALESCE(SUM(value),0) FROM utxo").fetchone()
        return n, total

    def count_spendable(self):
        n, total = self._db.execute(
            "SELECT COUNT(*), COALESCE(SUM(value),0) FROM utxo "
            "WHERE spendable=1").fetchone()
        return n, total

    def find_by_spk(self, spk):
        """All snapshot outputs paying to lock script spk: [(key, entry)]."""
        out = []
        for txid_b, vout, value, is_cb, cb_h in self._db.execute(
                "SELECT txid, vout, value, is_cb, cb_h FROM utxo WHERE spk=?",
                (bytes(spk),)):
            out.append(((bytes(txid_b), vout),
                        (value, bytes(spk), is_cb, cb_h)))
        return out


def build_snapshot_db(dat_path, db_path, snapshot_hash_hex, height,
                      log=print):
    """Build utxo.db from a verified snapshot_968698.dat. Deterministic."""
    import hashlib
    digest = _sha256d_file(dat_path)
    if digest != snapshot_hash_hex:
        raise ValueError(
            f"snapshot hash mismatch: file={digest} expected={snapshot_hash_hex}")
    if os.path.exists(db_path):
        os.remove(db_path)
    db = sqlite3.connect(db_path)
    db.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")
    db.executescript(SCHEMA)
    n = _load_dat_into_db(db, dat_path, log)
    log("creating spk index...")
    db.execute("CREATE INDEX IF NOT EXISTS idx_spk ON utxo(spk)")
    db.execute("INSERT INTO meta(k,v) VALUES "
               "('snapshot_hash',?),('height',?),('format',?)",
               (snapshot_hash_hex, str(height), "fork-snapshot-v1"))
    db.commit()
    cnt, total = db.execute(
        "SELECT COUNT(*), COALESCE(SUM(value),0) FROM utxo").fetchone()
    assert cnt == n, (cnt, n)
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    db.commit()
    db.close()
    log(f"snapshot DB built: {cnt} outputs, {total/1e8:.2f} EXCAL -> {db_path}")
    return cnt, total


def _sha256d_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return hashlib.sha256(h.digest()).hexdigest()


def _read_varint(f):
    b = f.read(1)
    if not b:
        raise EOFError
    n = b[0]
    if n < 0xfd:
        return n
    if n == 0xfd:
        return int.from_bytes(f.read(2), "little")
    if n == 0xfe:
        return int.from_bytes(f.read(4), "little")
    return int.from_bytes(f.read(8), "little")


def _load_dat_into_db(db, dat_path, log):
    """Stream snapshot_968698.dat records into the utxo table."""
    import struct
    n = 0
    batch = []
    with open(dat_path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        assert magic == 0x45425346, f"bad snapshot magic {magic:#x}"
        ver = struct.unpack("<I", f.read(4))[0]
        assert ver == 1, f"bad snapshot version {ver}"
        height = struct.unpack("<I", f.read(4))[0]
        count = struct.unpack("<Q", f.read(8))[0]
        log(f"snapshot v{ver} height={height} count={count}")
        for _ in range(count):
            txid_b = f.read(32)
            vout = struct.unpack("<I", f.read(4))[0]
            value = struct.unpack("<Q", f.read(8))[0]
            ll = _read_varint(f)
            lock = f.read(ll)
            flags = f.read(1)[0]
            batch.append((txid_b, vout, value, lock, 0, 0,
                          1 if flags & 1 else 0))
            n += 1
            if len(batch) >= 50000:
                db.executemany(
                    "INSERT INTO utxo(txid,vout,value,spk,is_cb,cb_h,"
                    "spendable) VALUES (?,?,?,?,?,?,?)", batch)
                batch = []
                if n % 1000000 == 0:
                    log(f"  ... {n//1000000}M / {count//1000000}M")
        if batch:
            db.executemany(
                "INSERT INTO utxo(txid,vout,value,spk,is_cb,cb_h,spendable)"
                " VALUES (?,?,?,?,?,?,?)", batch)
    assert n == count, (n, count)
    return n


class UtxoSet:
    """Dict-compatible UTXO set: overlay (fork outputs) + spent-tombstones
    over an immutable SnapshotDB. Entries are [(value, spk, is_cb, cb_h)]."""

    def __init__(self, snapshot=None, overlay=None, spent=None):
        self.snapshot = snapshot
        self.overlay = overlay if overlay is not None else {}
        self.spent = spent if spent is not None else set()

    # ---------------------------------------------------------- dict API
    def get(self, key, default=None):
        if key in self.spent:
            return default
        if key in self.overlay:
            return self.overlay[key]
        if self.snapshot is not None:
            r = self.snapshot.get(key)
            if r is not None:
                return r
        return default

    def __getitem__(self, key):
        r = self.get(key)
        if r is None:
            raise KeyError(key)
        return r

    def __setitem__(self, key, entries):
        self.overlay[key] = list(entries)
        self.spent.discard(key)

    def __delitem__(self, key):
        if key in self.overlay:
            del self.overlay[key]
            return
        if key in self.spent:
            raise KeyError(key)
        if self.snapshot is not None and self.snapshot.get(key) is not None:
            self.spent.add(key)
            return
        raise KeyError(key)

    def setdefault(self, key, default):
        if key in self.spent:
            raise AssertionError("re-creating a spent snapshot output")
        if key in self.overlay:
            return self.overlay[key]
        if self.snapshot is not None and self.snapshot.get(key) is not None:
            raise AssertionError("duplicate output creation")
        self.overlay[key] = default
        return default

    def __contains__(self, key):
        return self.get(key) is not None

    def copy(self):
        """Cheap copy: shares the immutable snapshot."""
        return UtxoSet(self.snapshot,
                       {k: list(v) for k, v in self.overlay.items()},
                       set(self.spent))

    # ---------------------------------------------------------- queries
    def stats(self):
        n = total = 0
        if self.snapshot is not None:
            n, total = self.snapshot.stats()
            n -= len(self.spent)
            for key in self.spent:
                e = self.snapshot.get(key)
                if e:
                    total -= e[0][0]
        for entries in self.overlay.values():
            for value, _s, _c, _h in entries:
                n += 1
                total += value
        return n, total

    def find_by_spk(self, spk):
        """[(key, entry)] paying to lock script spk (snapshot + overlay)."""
        out = []
        if self.snapshot is not None:
            for key, entry in self.snapshot.find_by_spk(bytes(spk)):
                if key not in self.spent:
                    out.append((key, entry))
        for key, entries in self.overlay.items():
            for e in entries:
                if e[1] == bytes(spk):
                    out.append((key, e))
        return out

    # Iteration over the full set is O(snapshot). Provided for
    # compatibility; prefer find_by_spk / stats for hot paths.
    def items(self):
        if self.snapshot is not None:
            db = self.snapshot._db
            for txid_b, vout, value, spk, is_cb, cb_h in db.execute(
                    "SELECT txid, vout, value, spk, is_cb, cb_h FROM utxo"):
                key = (bytes(txid_b), vout)
                if key not in self.spent and key not in self.overlay:
                    yield key, [(value, bytes(spk), is_cb, cb_h)]
        for key, entries in self.overlay.items():
            yield key, entries

    def values(self):
        for _k, v in self.items():
            yield v
