"""
FastAPI‑служба журнального Merkle‑лог‑хранилища.

Эндпоинты
---------
POST /log                 → добавить запись
GET  /root/latest         → последний snapshot
GET  /root/{snap_id}      → snapshot по ID
GET  /proof/{index}       → доказательство; ?snap=ID для старого снимка
"""

from __future__ import annotations

import base64
import hashlib
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from app.smt import SparseMerkleTree
from app.signing import sign_root, verify_root
from app.storage import Storage
from app.models import LogRecordIn, LogRecordOut, SnapshotOut, ProofOut

from functools import lru_cache 

# --- параметры сервиса --- #
DB_PATH = "api_log.db"
DEPTH = 8  # для курсовой и тестов; в «бою» ставьте 256

app = FastAPI(title="Merkle‑Log API")
_store = Storage(DB_PATH)
_tree = SparseMerkleTree(DEPTH)


def _rebuild_tree() -> None:
    """При старте восстанавливаем дерево из БД (по последнему snapshot)."""
    snap = _store.latest_snapshot()
    if not snap:
        return  # база пуста

    snap_id = snap[0]
    leaves: Dict[int, bytes] = _store.leaves_upto(snap_id)
    for idx in sorted(leaves.keys()):
        _tree.add(b"dummy")  # добавляем «пустышку», чтобы соблюсти индексы
        _tree._nodes[(0, idx)] = leaves[idx]  # подменяем leaf‑хеш напрямую
    # теперь вручную пересчитываем внутренние вершины
    for idx in sorted(leaves.keys()):
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

# ---------- утилиты ---------- #
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# ---------- эндпоинты ---------- #
@app.post("/log", response_model=LogRecordOut)
def add_log(item: LogRecordIn):
    """Добавить новую строку лога и зафиксировать snapshot."""
    idx = _tree.add(item.data.encode())
    leaf_hash = hashlib.sha256(item.data.encode()).digest()

    root = _tree.root()
    sig = sign_root(root)
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
    Доказательство включения листа `index`.
    Если ?snap=ID → строим proof относительно указанного snapshot‑a,
    иначе — относительно последнего.
    """
    snap_tup = (
        _store.latest_snapshot() if snap is None else _store.get_snapshot(snap)
    )
    if not snap_tup:
        raise HTTPException(status_code=404, detail="snapshot not found")
    sid, root, sig, _ = snap_tup
    if not verify_root(root, sig):
        raise HTTPException(status_code=400, detail="root signature invalid")

    # ► строим proof: либо из «живого» дерева, либо из реконструированного
    if snap is None or sid == _store.latest_snapshot()[0]:
        proof_bytes = _tree.proof(index)
    else:
        try:
            tree = _tree_for_snapshot(sid)
        except ValueError:
            raise HTTPException(status_code=404, detail="index not present in snapshot")
        proof_bytes = tree.proof(index)

    leaf_hash = hashlib.sha256(f"record {index}".encode()).digest()
    return ProofOut(
        snapshot_id=sid,
        root=b64(root),
        signature=b64(sig),
        index=index,
        leaf=b64(leaf_hash),
        proof=[b64(h) for h in proof_bytes],
    )

@lru_cache(maxsize=64)
def _tree_for_snapshot(snap_id: int) -> SparseMerkleTree:
    """
    Собрать SparseMerkleTree, содержащий все листья,
    существовавшие к моменту snapshot_id.
    Кэшируем, чтобы повторные запросы были O(1).
    """
    leaves = _store.leaves_upto(snap_id)          # {index: leaf_hash}
    if not leaves:
        raise ValueError("snapshot has no leaves")

    t = SparseMerkleTree(DEPTH)
    max_idx = max(leaves.keys())

    # быстро «создаём» пустое дерево нужной ширины
    for _ in range(max_idx + 1):
        t.add(b"0")                    # placeholder
    # подменяем реальные leaf‑хеши
    for idx, h in leaves.items():
        t._nodes[(0, idx)] = h

    # пересчитываем все внутренние вершины
    for idx in leaves.keys():
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