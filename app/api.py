"""
FastAPI‑служба журнального Merkle‑лог‑хранилища.
-----------------------------------------------
POST /log                 → добавить запись
GET  /root/latest         → последний snapshot
GET  /root/{snap_id}      → snapshot по ID
GET  /proof/{index}       → Merkle‑доказательство; ?snap=ID для старого снимка
"""

from __future__ import annotations

import base64, hashlib
from typing import Dict, List, Optional
from functools import lru_cache

from fastapi import FastAPI, HTTPException, Query

from app.smt import SparseMerkleTree
from app.signing import sign_root, verify_root
from app.storage import Storage
from app.models import LogRecordIn, LogRecordOut, SnapshotOut, ProofOut

DB_PATH = "api_log.db"
DEPTH   = 8          

app    = FastAPI(title="Merkle‑Log API")
_store = Storage(DB_PATH)
_tree  = SparseMerkleTree(DEPTH)

def _rebuild_tree() -> None:
    snap = _store.latest_snapshot()
    if not snap:
        return
    snap_id = snap[0]
    leaves: Dict[int, bytes] = _store.leaves_upto(snap_id)

    for idx in sorted(leaves):
        _tree.add(b"dummy")                 # placeholder, чтобы занять индекс
        _tree._nodes[(0, idx)] = leaves[idx]

    for idx in leaves:
        h = leaves[idx]
        level, pos = 0, idx
        while level < DEPTH:
            sibling_pos = pos ^ 1
            sibling_hash = _tree._nodes.get(
                (level, sibling_pos), _tree.zero_hashes[level]
            )
            concat = h + sibling_hash if pos % 2 == 0 else sibling_hash + h
            h = hashlib.sha256(concat).digest()
            level += 1
            pos //= 2
            _tree._nodes[(level, pos)] = h

_rebuild_tree()

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _get_leaf_or_404(index: int, snap_id: int) -> bytes:
    leaf = _store.get_leaf(index, snap_id)
    if leaf is None:
        raise HTTPException(status_code=404, detail="index not present in snapshot")
    return leaf

@app.post("/log", response_model=LogRecordOut)
def add_log(item: LogRecordIn):
    idx = _tree.add(item.data.encode())
    leaf_hash = hashlib.sha256(item.data.encode()).digest()

    root = _tree.root()
    sig  = sign_root(root)
    snap_id = _store.create_snapshot(root, sig)
    _store.insert_leaf(idx, leaf_hash, snap_id)

    return LogRecordOut(index=idx, snapshot_id=snap_id)


@app.get("/root/latest", response_model=SnapshotOut)
def get_latest_root():
    snap = _store.latest_snapshot()
    if not snap:
        raise HTTPException(status_code=404, detail="no snapshots")
    sid, root, sig, ts = snap
    return SnapshotOut(
        snapshot_id=sid,
        root=b64(root),
        signature=b64(sig),
        timestamp=ts,
        signature_ok=verify_root(root, sig),
    )


@app.get("/root/{snap_id}", response_model=SnapshotOut)
def get_root(snap_id: int):
    snap = _store.get_snapshot(snap_id)
    if not snap:
        raise HTTPException(status_code=404, detail="snapshot not found")
    sid, root, sig, ts = snap
    return SnapshotOut(
        snapshot_id=sid,
        root=b64(root),
        signature=b64(sig),
        timestamp=ts,
        signature_ok=verify_root(root, sig),
    )


@app.get("/proof/{index}", response_model=ProofOut)
def get_proof(index: int, snap: Optional[int] = Query(None)):
    """
    Возвращает Merkle‑proof для листа `index`.
    Если ?snap=ID — proof строится относительно указанного snapshot‑а,
    иначе — относительно самого последнего.
    """
    snap_tup = _store.latest_snapshot() if snap is None else _store.get_snapshot(snap)
    if not snap_tup:
        raise HTTPException(status_code=404, detail="snapshot not found")
    sid, root, sig, _ = snap_tup
    if not verify_root(root, sig):
        raise HTTPException(status_code=400, detail="root signature invalid")

    leaf_hash = _get_leaf_or_404(index, sid)

    if snap is None or sid == _store.latest_snapshot()[0]:
        proof_bytes = _tree.proof(index)
    else:
        proof_bytes = _tree_for_snapshot(sid).proof(index)

    return ProofOut(
        snapshot_id=sid,
        root=b64(root),
        signature=b64(sig),
        index=index,
        leaf=b64(leaf_hash),
        proof=[b64(h) for h in proof_bytes],
    )

# Реконструкция дерева для прошлого snapshot
@lru_cache(maxsize=64)
def _tree_for_snapshot(snap_id: int) -> SparseMerkleTree:
    leaves = _store.leaves_upto(snap_id)
    if not leaves:
        raise ValueError("snapshot has no leaves")

    t = SparseMerkleTree(DEPTH)
    max_idx = max(leaves)
    for _ in range(max_idx + 1):
        t.add(b"0")                       # тк потом все равно значение изменится
    for idx, h in leaves.items():
        t._nodes[(0, idx)] = h

    for idx in leaves:
        h = leaves[idx]
        level, pos = 0, idx
        while level < DEPTH:
            sibling_pos = pos ^ 1
            sibling_hash = t._nodes.get(
                (level, sibling_pos), t.zero_hashes[level]
            )
            concat = h + sibling_hash if pos % 2 == 0 else sibling_hash + h
            h = hashlib.sha256(concat).digest()
            level += 1
            pos //= 2
            t._nodes[(level, pos)] = h
    return t
