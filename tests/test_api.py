import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app.api import app, DEPTH
from app.signing import verify_root
from app.smt import SparseMerkleTree

client = TestClient(app)


def test_end_to_end():
    # 1) добавляем запись
    r = client.post("/log", json={"data": "hello api"})
    assert r.status_code == 200
    idx = r.json()["index"]
    snap_id = r.json()["snapshot_id"]

    # 2) получаем свежий root
    r2 = client.get("/root/latest")
    body = r2.json()
    root = base64.b64decode(body["root"])
    sig = base64.b64decode(body["signature"])
    assert verify_root(root, sig)
    assert body["snapshot_id"] == snap_id

    # 3) запрашиваем proof
    r3 = client.get(f"/proof/{idx}")
    proof_body = r3.json()
    proof_b = [base64.b64decode(p) for p in proof_body["proof"]]
    leaf = hashlib.sha256("hello api".encode()).digest()
    assert SparseMerkleTree.verify_proof(leaf, idx, proof_b, root, DEPTH)
