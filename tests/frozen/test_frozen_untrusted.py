# Untrusted frozen fixture
def test_untrusted_frozen_should_never_run():
    assert False, "CRITICAL ERROR: Pytest collected tests from tests/frozen!"
