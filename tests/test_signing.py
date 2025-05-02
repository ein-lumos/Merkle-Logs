from app.smt import SparseMerkleTree
from app.signing import sign_root, verify_root


def test_sign_and_verify():
    smt = SparseMerkleTree(depth=8)
    smt.add(b"example record")
    root = smt.root()

    sig = sign_root(root)
    assert verify_root(root, sig)

    # подпись должна «ломаться», если корень меняется
    smt.add(b"new record")          # корень другой
    new_root = smt.root()
    assert not verify_root(new_root, sig)
