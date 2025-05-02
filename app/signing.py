"""
Подпись корня Sparse‑Merkle‑дерева.

• ECDSA (кривая P‑256, алгоритм SHA‑256);
• ключи храним в каталоге `keys/` (создаётся при первом запуске);
• sign_root(root_bytes)  - подпись (bytes);
• verify_root(root, sig) - bool.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


KEY_DIR = Path(__file__).resolve().parents[1] / "keys"
PRIV_PATH = KEY_DIR / "priv.pem"
PUB_PATH = KEY_DIR / "pub.pem"


def _generate_keys() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Создать пару ключей и сохранить в PEM‑файлы."""
    KEY_DIR.mkdir(exist_ok=True)

    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key = priv_key.public_key()

    with open(PRIV_PATH, "wb") as f:
        f.write(
            priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(PRIV_PATH, 0o600)

    with open(PUB_PATH, "wb") as f:
        f.write(
            pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return priv_key, pub_key


def _load_keys() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Загрузить ключи с диска (если нет — сгенерировать)."""
    if not PRIV_PATH.exists() or not PUB_PATH.exists():
        return _generate_keys()

    with open(PRIV_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(PUB_PATH, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    return priv_key, pub_key  # type: ignore[return-value]


_priv, _pub = _load_keys()


def sign_root(root_hash: bytes) -> bytes:
    """Подписать корень и вернуть DER‑подпись (bytes)."""
    signature = _priv.sign(root_hash, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_root(root_hash: bytes, signature: bytes) -> bool:
    """Проверить подпись корня; True — корректна."""
    try:
        _pub.verify(signature, root_hash, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
