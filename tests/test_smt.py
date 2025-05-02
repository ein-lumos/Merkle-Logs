import hashlib
from app.smt import SparseMerkleTree


def test_insert_and_proof():
    """Проверяем: после вставок proof действительно восстанавливает корень."""
    depth = 8                     # маленькая глубина — тесты работают мгновенно
    smt = SparseMerkleTree(depth)

    records = [f"record {i}".encode() for i in range(20)]
    indices = [smt.add(r) for r in records]
    current_root = smt.root()

    for idx, rec in zip(indices, records):
        leaf = hashlib.sha256(rec).digest()
        proof = smt.proof(idx)
        assert SparseMerkleTree.verify_proof(leaf, idx, proof, current_root, depth)
