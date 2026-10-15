import os
import pytest

FORBIDDEN_COLLECTION_DIRS = {
    "tests/fixtures",
    "tests/dev",
    "tests/frozen",
    "benchmark",
}

# Explicit test-only 32-byte HMAC secret (64 hex characters) injected exclusively
# during pytest executions. Production code fails closed if CANARY_HMAC_SECRET is unset.
TEST_CANARY_HMAC_SECRET = (
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


@pytest.fixture(autouse=True)
def setup_test_canary_hmac_secret(monkeypatch) -> None:
    """Inject deterministic test-only HMAC key unless explicitly overridden by test."""
    if "CANARY_HMAC_SECRET" not in os.environ:
        monkeypatch.setenv("CANARY_HMAC_SECRET", TEST_CANARY_HMAC_SECRET)



def pytest_collection_modifyitems(session, config, items) -> None:
    """Strict security guard asserting pytest never collects tests from untrusted directories.

    Fails closed immediately if tests from fixtures, dev scenarios, frozen benchmark,
    or benchmark directories are collected as executable tests.
    """
    for item in items:
        # Normalize path with forward slashes
        fspath_str = str(item.fspath).replace("\\", "/")

        for forbidden in FORBIDDEN_COLLECTION_DIRS:
            # Check if path contains the forbidden directory segment
            if f"/{forbidden}/" in fspath_str or fspath_str.startswith(f"{forbidden}/") or fspath_str.endswith(f"/{forbidden}"):
                raise pytest.UsageError(
                    f"CRITICAL SECURITY GUARD VIOLATION: Pytest collected item '{item.nodeid}' "
                    f"from untrusted directory '{forbidden}'. "
                    f"Untrusted fixture data must NEVER be collected or executed as test code."
                )
