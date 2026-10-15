# Untrusted benchmark fixture
def test_untrusted_benchmark_should_never_run():
    assert False, "CRITICAL ERROR: Pytest collected tests from benchmark!"
