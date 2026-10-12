import pytest
from backend.app.scope_guard import ScopeGuard, ScopeGuardError

def test_scope_guard_normalizes_url():
    norm, host, scheme = ScopeGuard.normalize_target("example.com")
    assert norm == "https://example.com"
    assert host == "example.com"
    assert scheme == "https"

def test_scope_guard_blocks_localhost():
    with pytest.raises(ScopeGuardError, match="prohibited"):
        ScopeGuard.normalize_target("http://localhost:8000")

    with pytest.raises(ScopeGuardError, match="prohibited"):
        ScopeGuard.normalize_target("http://127.0.0.1")

def test_scope_guard_blocks_cloud_metadata():
    with pytest.raises(ScopeGuardError, match="metadata"):
        ScopeGuard.normalize_target("http://169.254.169.254/latest/meta-data")

def test_scope_guard_blocks_unauthorized_scope():
    with pytest.raises(ScopeGuardError, match="out of approved scope"):
        ScopeGuard.validate_destination_network(
            target_url="https://evil.com",
            allowed_host="example.com",
            allow_subdomains=False,
            user_authorized=True
        )

def test_scope_guard_blocks_excluded_host():
    with pytest.raises(ScopeGuardError, match="exclusion list"):
        ScopeGuard.validate_destination_network(
            target_url="https://payment.example.com",
            allowed_host="example.com",
            allow_subdomains=True,
            excluded_hosts=["payment.example.com"],
            user_authorized=True
        )

def test_scope_guard_blocks_unauthorized_flag():
    with pytest.raises(ScopeGuardError, match="not authorized"):
        ScopeGuard.validate_destination_network(
            target_url="https://example.com",
            user_authorized=False
        )
