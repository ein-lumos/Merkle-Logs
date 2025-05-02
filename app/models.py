from pydantic import BaseModel
from typing import List


class LogRecordIn(BaseModel):
    data: str


class LogRecordOut(BaseModel):
    index: int
    snapshot_id: int


class SnapshotOut(BaseModel):
    snapshot_id: int
    root: str
    signature: str
    timestamp: str
    signature_ok: bool


class ProofOut(BaseModel):
    snapshot_id: int
    root: str
    signature: str
    index: int
    leaf: str
    proof: List[str]
