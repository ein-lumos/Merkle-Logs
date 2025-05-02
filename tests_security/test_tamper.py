"""
Проверяем, что любые попытки подмены
— записи, proof или подписи — обнаруживаются.
Запуск:  pytest -q tests_security/test_tamper.py
"""

import base64, hashlib, os, tempfile, importlib
from fastapi.testclient import TestClient

# ─── изолируемся собственной БД ───
tmpdb = tempfile.NamedTemporaryFile(delete=False).name
os.environ["MERKLE_LOG_DB"] = tmpdb
import app.api as api
importlib.reload(api)                         # чтобы app поднялся с новой БД

from app.signing import verify_root           
from app.smt import SparseMerkleTree          

client = TestClient(api.app)
DEPTH = api.DEPTH

b64d = lambda s: base64.b64decode(s)


def test_tamper_detection():
    # 1) добавляем запись и получаем корректный proof
    data = "victim"
    idx  = client.post("/log", json={"data": data}).json()["index"]
    proof_json = client.get(f"/proof/{idx}").json()

    root   = b64d(proof_json["root"])
    sig    = b64d(proof_json["signature"])
    leaf   = b64d(proof_json["leaf"])
    proofb = [b64d(x) for x in proof_json["proof"]]

    # оригинальный набор должен проходить все проверки
    assert verify_root(root, sig)
    assert SparseMerkleTree.verify_proof(leaf, idx, proofb, root, DEPTH)

    # 2) подмена листа (изменили 1 бит)
    fake_leaf = (int.from_bytes(leaf, "big") ^ 1).to_bytes(32, "big")
    assert not SparseMerkleTree.verify_proof(fake_leaf, idx, proofb, root, DEPTH)

    # 3) подмена первого хеша в proof
    bad_proof = proofb.copy()
    # меняем последний бит первого 32‑байтового хеша
    bad_proof[0] = bad_proof[0][:-1] + bytes([bad_proof[0][-1] ^ 1])
    assert not SparseMerkleTree.verify_proof(leaf, idx, bad_proof, root, DEPTH)

    # 4) подмена подписи (тоже 1 бит)
    bad_sig = sig[:-1] + bytes([sig[-1] ^ 1])
    assert not verify_root(root, bad_sig)
