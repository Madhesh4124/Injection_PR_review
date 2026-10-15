# This file is an untrusted fixture file.
# Pytest should NEVER collect or execute tests from tests/fixtures.
def test_untrusted_code_should_never_be_collected():
    assert False, "CRITICAL ERROR: Pytest collected tests from untrusted tests/fixtures!"
