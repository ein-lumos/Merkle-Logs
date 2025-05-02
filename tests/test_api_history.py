import base64, hashlib, os, tempfile, importlib
from fastapi.testclient import TestClient

# ------- изолируемся отдельной БД для этого теста -------------------------
tmpdb = tempfile.NamedTemporaryFile(delete=False).name
os.environ["MERKLE_LOG_DB"] = tmpdb
import app.api as api
importlib.reload(api)

from app.signing import verify_root
from app.smt import SparseMerkleTree

client = TestClient(api.app)
DEPTH = api.DEPTH
# --------------------------------------------------------------------------

def test_history_proof():
    # добавляем две записи, запоминаем snapshot первого добавления
    idxs = []
    first_snap_id = None
    for msg in ("past", "future"):
        r = client.post("/log", json={"data": msg}).json()
        idxs.append(r["index"])
        if first_snap_id is None:
            first_snap_id = r["snapshot_id"]

    # у последнего снимка ID должен быть больше, чем у первого
    latest = client.get("/root/latest").json()
    assert latest["snapshot_id"] > first_snap_id

    # ---------- проверяем proof ДЛЯ первого snapshot‑а ----------
    proof_json = client.get(f"/proof/{idxs[0]}?snap={first_snap_id}").json()
    root_b   = base64.b64decode(proof_json["root"])
    sig_b    = base64.b64decode(proof_json["signature"])
    proof_bs = [base64.b64decode(x) for x in proof_json["proof"]]
    leaf_b   = hashlib.sha256("past".encode()).digest()

    assert verify_root(root_b, sig_b)
    assert SparseMerkleTree.verify_proof(leaf_b, idxs[0], proof_bs, root_b, DEPTH)
