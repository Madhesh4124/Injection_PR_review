# Untrusted dev fixture
def test_untrusted_dev_should_never_run():
    assert False, "CRITICAL ERROR: Pytest collected tests from tests/dev!"
