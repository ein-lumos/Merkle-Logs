"""
SQLite‑хранилище для системы логов.

Таблицы
--------
leaves(id INTEGER PRIMARY KEY,
       hash BLOB NOT NULL,
       snapshot_id INTEGER NOT NULL)

snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT,
          root BLOB NOT NULL,
          signature BLOB NOT NULL,
          ts DATETIME DEFAULT CURRENT_TIMESTAMP)

Использование (в сервисе)
-------------------------
store = Storage("log.db")
snap_id = store.create_snapshot(root, sig)
store.insert_leaf(index, leaf_hash, snap_id)
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, Tuple, Optional


class Storage:
    def __init__(self, path: str | Path = "log.db") -> None:
        self.conn = sqlite3.connect(
            path,
            isolation_level=None,        # autocommit
            check_same_thread=False      # позволяем другим потокам пользоваться тем же conn
        )
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._create_tables()

    # ---------- schema ---------- #
    def _create_tables(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS leaves(
                   id          INTEGER PRIMARY KEY,
                   hash        BLOB    NOT NULL,
                   snapshot_id INTEGER NOT NULL)"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS snapshots(
                   id        INTEGER PRIMARY KEY AUTOINCREMENT,
                   root      BLOB    NOT NULL,
                   signature BLOB    NOT NULL,
                   ts        DATETIME DEFAULT CURRENT_TIMESTAMP)"""
        )

    # ---------- snapshots ---------- #
    def create_snapshot(self, root: bytes, signature: bytes) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO snapshots(root, signature) VALUES(?, ?)",
            (root, signature),
        )
        return cur.lastrowid

    def latest_snapshot(self) -> Optional[Tuple[int, bytes, bytes, str]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, root, signature, ts FROM snapshots ORDER BY id DESC LIMIT 1"
        )
        return cur.fetchone()

    def get_snapshot(self, snapshot_id: int) -> Optional[Tuple[int, bytes, bytes, str]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, root, signature, ts FROM snapshots WHERE id=?", (snapshot_id,)
        )
        return cur.fetchone()

    # ---------- leaves ---------- #
    def insert_leaf(self, index: int, leaf_hash: bytes, snapshot_id: int) -> None:
        self.conn.execute(
            "INSERT INTO leaves(id, hash, snapshot_id) VALUES(?, ?, ?)",
            (index, leaf_hash, snapshot_id),
        )

    def leaves_upto(self, snapshot_id: int) -> Dict[int, bytes]:
        """Вернуть {index: hash} для всех листьев, существовавших к указанному снимку."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, hash FROM leaves WHERE snapshot_id<=?", (snapshot_id,)
        )
        return {row[0]: row[1] for row in cur.fetchall()}
    
    def get_leaf(self, index: int, snapshot_id: int) -> bytes | None:
        """Вернуть хеш листа по индексу, существующий к моменту snapshot_id."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT hash FROM leaves "
            "WHERE id=? AND snapshot_id<=? "
            "ORDER BY snapshot_id DESC LIMIT 1",
            (index, snapshot_id),
        )
        row = cur.fetchone()
        return row[0] if row else None
