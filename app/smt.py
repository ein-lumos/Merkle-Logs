"""
Sparse Merkle Tree (SMT) — основа системы целостности логов.

• глубина по умолчанию 256 (под SHA‑256);
• add(data)        - индекс вставленной записи;
• root()           - текущий корневой хеш;
• proof(index)     - список «соседних» хешей (длина = depth);
• verify_proof(...) - статический метод для быстрой проверки на стороне клиента.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Tuple


class SparseMerkleTree:
    def __init__(self, depth: int = 256) -> None:
        self.depth: int = depth
        self.zero_hashes: List[bytes] = [b"\x00" * 32]
        for _ in range(1, depth + 1):
            self.zero_hashes.append(
                hashlib.sha256(self.zero_hashes[-1] + self.zero_hashes[-1]).digest()
            )

        # (level, position) → хеш‑значение
        self._nodes: Dict[Tuple[int, int], bytes] = {}
        self._size: int = 0  

    @staticmethod
    def _h(data: bytes) -> bytes:  
        return hashlib.sha256(data).digest()

    def add(self, data: bytes) -> int:
        """Добавить новый лист; вернуть его индекс."""
        idx = self._size
        self._size += 1

        h = self._h(data)
        level, pos = 0, idx
        self._nodes[(level, pos)] = h

        while level < self.depth:
            sibling_pos = pos ^ 1  
            sibling_hash = self._nodes.get((level, sibling_pos), self.zero_hashes[level])

            concat = h + sibling_hash if pos % 2 == 0 else sibling_hash + h
            h = self._h(concat)

            level += 1
            pos //= 2
            self._nodes[(level, pos)] = h

        return idx

    def root(self) -> bytes:
        """Текущий корень дерева (если ещё пусто — «нулевой» хеш)."""
        return self._nodes.get((self.depth, 0), self.zero_hashes[self.depth])

    def proof(self, index: int) -> List[bytes]:
        """Вернуть Merkle‑доказательство для листа с заданным индексом."""
        if index >= self._size:
            raise IndexError("leaf index out of range")

        proof: List[bytes] = []
        pos = index
        for level in range(self.depth):
            sibling_pos = pos ^ 1
            proof.append(self._nodes.get((level, sibling_pos), self.zero_hashes[level]))
            pos //= 2
        return proof

    @staticmethod
    def verify_proof(
        leaf_hash: bytes,
        index: int,
        proof: List[bytes],
        expected_root: bytes,
        depth: int = 256,
    ) -> bool:
        """Проверить, что leaf_hash действительно принадлежит дереву с корнем expected_root."""
        if len(proof) != depth:
            return False

        h = leaf_hash
        pos = index
        for level in range(depth):
            sibling = proof[level]
            concat = h + sibling if pos % 2 == 0 else sibling + h
            h = hashlib.sha256(concat).digest()
            pos //= 2

        return h == expected_root
