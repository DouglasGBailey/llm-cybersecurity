from src.history_store import HistoryStore


def make_store(tmp_path):
    return HistoryStore(db_path=tmp_path / "history.db")


def test_no_prior_run_returns_none(tmp_path):
    store = make_store(tmp_path)
    assert store.get_previous_run("local-dvwa") is None


def test_save_and_retrieve_round_trip(tmp_path):
    store = make_store(tmp_path)
    findings = [{"type": "open-port", "port": 80}]
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", findings)

    prev = store.get_previous_run("local-dvwa")
    assert prev is not None
    assert prev["timestamp"] == "2026-08-13T00:00:00+00:00"
    assert prev["findings"] == findings


def test_get_previous_run_returns_most_recent(tmp_path):
    store = make_store(tmp_path)
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", [{"type": "a"}])
    store.save_run("local-dvwa", "2026-08-13T01:00:00+00:00", [{"type": "b"}])
    store.save_run("local-dvwa", "2026-08-13T02:00:00+00:00", [{"type": "c"}])

    prev = store.get_previous_run("local-dvwa")
    assert prev["timestamp"] == "2026-08-13T02:00:00+00:00"
    assert prev["findings"] == [{"type": "c"}]


def test_targets_are_isolated(tmp_path):
    store = make_store(tmp_path)
    store.save_run("target-a", "2026-08-13T00:00:00+00:00", [{"type": "a-finding"}])
    store.save_run("target-b", "2026-08-13T00:00:00+00:00", [{"type": "b-finding"}])

    a = store.get_previous_run("target-a")
    b = store.get_previous_run("target-b")
    assert a["findings"] == [{"type": "a-finding"}]
    assert b["findings"] == [{"type": "b-finding"}]


def test_get_run_history_ordering_and_limit(tmp_path):
    store = make_store(tmp_path)
    for i in range(5):
        store.save_run("local-dvwa", f"2026-08-13T0{i}:00:00+00:00", [{"type": f"run-{i}"}])

    history = store.get_run_history("local-dvwa", limit=3)
    assert len(history) == 3
    # newest first
    assert history[0]["findings"] == [{"type": "run-4"}]
    assert history[1]["findings"] == [{"type": "run-3"}]
    assert history[2]["findings"] == [{"type": "run-2"}]


def test_db_file_created_on_first_use(tmp_path):
    db_path = tmp_path / "nested" / "history.db"
    assert not db_path.exists()
    HistoryStore(db_path=db_path)
    assert db_path.exists()
