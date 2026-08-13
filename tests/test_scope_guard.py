import textwrap

import pytest

from src.scope_guard import OutOfScopeError, ScopeConfigError, ScopeGuard


def write_scope(tmp_path, content):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_missing_scope_file_raises(tmp_path):
    with pytest.raises(ScopeConfigError):
        ScopeGuard(tmp_path / "does-not-exist.yaml")


def test_empty_targets_raises(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets: []
        excluded: []
    """)
    with pytest.raises(ScopeConfigError):
        ScopeGuard(p)


def test_exact_ip_is_authorized(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
    """)
    guard = ScopeGuard(p)
    assert guard.is_authorized("127.0.0.1") is True
    guard.authorize("127.0.0.1")  # should not raise


def test_unlisted_ip_is_not_authorized(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
    """)
    guard = ScopeGuard(p)
    assert guard.is_authorized("8.8.8.8") is False
    with pytest.raises(OutOfScopeError):
        guard.authorize("8.8.8.8")


def test_cidr_range_authorizes_member_ip(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: lab-subnet
            host: 192.168.56.0/24
        excluded: []
    """)
    guard = ScopeGuard(p)
    assert guard.is_authorized("192.168.56.42") is True
    assert guard.is_authorized("192.168.57.1") is False


def test_exclusion_overrides_cidr_match(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: lab-subnet
            host: 192.168.56.0/24
        excluded:
          - 192.168.56.1
    """)
    guard = ScopeGuard(p)
    assert guard.is_authorized("192.168.56.1") is False
    assert guard.is_authorized("192.168.56.42") is True


def test_resolve_target_by_name(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local-dvwa
            host: 127.0.0.1
            notes: test box
        excluded: []
    """)
    guard = ScopeGuard(p)
    target = guard.resolve_target("local-dvwa")
    assert target.host == "127.0.0.1"
    assert target.notes == "test box"

    with pytest.raises(OutOfScopeError):
        guard.resolve_target("not-a-real-target")


def test_max_scan_rate_default_and_override(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
    """)
    guard = ScopeGuard(p)
    assert guard.scope.max_scan_rate == 5.0

    p2 = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        max_scan_rate: 2
    """)
    guard2 = ScopeGuard(p2)
    assert guard2.scope.max_scan_rate == 2.0


def test_no_authorized_code_paths_means_nothing_authorized(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
    """)
    guard = ScopeGuard(p)
    (tmp_path / "some_code").mkdir()
    assert guard.is_path_authorized(tmp_path / "some_code") is False
    with pytest.raises(OutOfScopeError):
        guard.authorize_path(tmp_path / "some_code")


def test_path_under_authorized_code_path_is_authorized(tmp_path):
    code_dir = tmp_path / "myproject"
    code_dir.mkdir()
    (code_dir / "subdir").mkdir()
    p = write_scope(tmp_path, f"""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_code_paths:
          - {code_dir}
    """)
    guard = ScopeGuard(p)
    assert guard.is_path_authorized(code_dir) is True
    assert guard.is_path_authorized(code_dir / "subdir") is True
    guard.authorize_path(code_dir / "subdir")  # should not raise


def test_path_outside_authorized_code_path_rejected(tmp_path):
    code_dir = tmp_path / "myproject"
    code_dir.mkdir()
    other_dir = tmp_path / "unrelated"
    other_dir.mkdir()
    p = write_scope(tmp_path, f"""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_code_paths:
          - {code_dir}
    """)
    guard = ScopeGuard(p)
    assert guard.is_path_authorized(other_dir) is False
    with pytest.raises(OutOfScopeError):
        guard.authorize_path(other_dir)


def test_nonexistent_path_is_not_authorized(tmp_path):
    code_dir = tmp_path / "myproject"
    code_dir.mkdir()
    p = write_scope(tmp_path, f"""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_code_paths:
          - {code_dir}
    """)
    guard = ScopeGuard(p)
    assert guard.is_path_authorized(code_dir / "does-not-exist") is False


def test_exploit_target_missing_resettable_rejected_at_load(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_exploit_targets:
          - name: local
            host: 127.0.0.1
    """)
    with pytest.raises(ScopeConfigError):
        ScopeGuard(p)


def test_exploit_target_resettable_false_rejected_at_load(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_exploit_targets:
          - name: local
            host: 127.0.0.1
            resettable: false
    """)
    with pytest.raises(ScopeConfigError):
        ScopeGuard(p)


def test_exploit_target_with_resettable_true_loads_successfully(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_exploit_targets:
          - name: local
            host: 127.0.0.1
            resettable: true
            known_vulnerabilities:
              sqli:
                - path: /vuln/
                  param: id
    """)
    guard = ScopeGuard(p)
    assert len(guard.scope.authorized_exploit_targets) == 1
    target = guard.scope.authorized_exploit_targets[0]
    assert target.resettable is True
    assert target.known_vulnerabilities["sqli"][0]["param"] == "id"


def test_resolve_exploit_target_by_name(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_exploit_targets:
          - name: local
            host: 127.0.0.1
            resettable: true
    """)
    guard = ScopeGuard(p)
    target = guard.resolve_exploit_target("local")
    assert target.host == "127.0.0.1"

    with pytest.raises(OutOfScopeError):
        guard.resolve_exploit_target("not-a-real-target")


def test_recon_authorization_does_not_imply_exploit_authorization(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
    """)
    guard = ScopeGuard(p)
    guard.authorize("127.0.0.1")  # recon-authorized, should not raise

    with pytest.raises(OutOfScopeError):
        guard.resolve_exploit_target("local")
    with pytest.raises(OutOfScopeError):
        guard.authorize_exploit("127.0.0.1")


def test_authorize_exploit_happy_path(tmp_path):
    p = write_scope(tmp_path, """
        authorized_targets:
          - name: local
            host: 127.0.0.1
        authorized_exploit_targets:
          - name: local
            host: 127.0.0.1
            resettable: true
    """)
    guard = ScopeGuard(p)
    guard.authorize_exploit("127.0.0.1")  # should not raise
