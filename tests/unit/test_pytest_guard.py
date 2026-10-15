"""Guard test asserting that pytest collection ignores all untrusted directories."""

import subprocess
import sys
import pytest


FORBIDDEN_PREFIXES = (
    "tests/fixtures",
    "tests\\fixtures",
    "tests/dev",
    "tests\\dev",
    "tests/frozen",
    "tests\\frozen",
    "benchmark",
)


def test_pytest_collect_guard_ignores_untrusted_dirs() -> None:
    """Assert zero tests are collected from untrusted directories during default pytest collection."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )

    output = result.stdout + "\n" + result.stderr

    for line in output.splitlines():
        line_clean = line.strip()
        for forbidden in FORBIDDEN_PREFIXES:
            assert not line_clean.startswith(forbidden), (
                f"Security Guard Failure: Pytest collected tests from untrusted directory '{forbidden}': {line_clean}"
            )


@pytest.mark.parametrize(
    "untrusted_test_path,expected_dir",
    [
        ("tests/fixtures/test_fixture_untrusted.py", "tests/fixtures"),
        ("tests/dev/test_dev_untrusted.py", "tests/dev"),
        ("tests/frozen/test_frozen_untrusted.py", "tests/frozen"),
        ("benchmark/test_benchmark_untrusted.py", "benchmark"),
    ],
)
def test_pytest_hook_aborts_on_explicit_untrusted_collection(
    untrusted_test_path: str, expected_dir: str
) -> None:
    """Assert that even if a user explicitly passes an untrusted directory, conftest hook aborts."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", untrusted_test_path],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + "\n" + result.stderr
    assert result.returncode != 0
    assert "CRITICAL SECURITY GUARD VIOLATION" in output
    assert expected_dir in output

