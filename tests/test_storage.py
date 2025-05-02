from app.storage import Storage


def test_create_and_retrieve_snapshot():
    store = Storage(":memory:")           # БД в RAM → тесты быстрые
    root = b"\x00" * 32
    sig = b"\x11" * 70

    snap_id = store.create_snapshot(root, sig)
    snap = store.latest_snapshot()

    assert snap is not None
    assert snap[0] == snap_id
    assert snap[1] == root
    assert snap[2] == sig


def test_insert_and_fetch_leaves():
    store = Storage(":memory:")
    snap1 = store.create_snapshot(b"A" * 32, b"sig1")
    store.insert_leaf(0, b"h" * 32, snap1)
    store.insert_leaf(1, b"q" * 32, snap1)

    leaves = store.leaves_upto(snap1)
    assert leaves == {0: b"h" * 32, 1: b"q" * 32}

    # второй снимок — новые листья
    snap2 = store.create_snapshot(b"B" * 32, b"sig2")
    store.insert_leaf(2, b"z" * 32, snap2)

    leaves2 = store.leaves_upto(snap2)
    assert 2 in leaves2 and leaves2[2] == b"z" * 32
