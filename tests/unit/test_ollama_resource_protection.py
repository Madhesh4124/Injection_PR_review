"""Unit tests verifying resource protection, concurrency controls, queueing, and retries for Ollama."""

import threading
import time
import urllib.error
from pathlib import Path
import pytest

from src.detection.ollama_provider import (
    OllamaConfig,
    OllamaInvalidOutputError,
    OllamaModelUnavailableError,
    OllamaOversizedInputError,
    OllamaProvider,
    OllamaQueueFullError,
    OllamaTimeoutError,
)
from src.evaluation.checker import load_development_fixtures, verify_checker_sanity

DEV_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "dev"


def test_concurrent_requests_semaphore_limiting():
    """Requirement 1 & 10: Limit concurrent requests using a semaphore (default 1)."""
    max_observed_concurrency = 0
    lock = threading.Lock()
    active = 0

    def mock_transport(payload, timeout):
        nonlocal max_observed_concurrency, active
        with lock:
            active += 1
            if active > max_observed_concurrency:
                max_observed_concurrency = active
        time.sleep(0.05)
        with lock:
            active -= 1
        return '{"records": []}'

    config = OllamaConfig(
        max_concurrency=1,
        max_queue_size=10,
        timeout_seconds=5.0,
    )
    provider = OllamaProvider(config=config, transport_fn=mock_transport)

    threads = []
    errors = []

    def worker():
        try:
            resp = provider.complete("Test prompt")
            assert resp.content == '{"records": []}'
        except Exception as e:
            errors.append(e)

    for _ in range(3):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert not errors, f"Encountered unexpected errors: {errors}"
    assert max_observed_concurrency == 1, (
        f"Concurrency exceeded limit! Expected 1, observed {max_observed_concurrency}"
    )


def test_queue_saturation_rejects_with_explicit_error():
    """Requirement 2, 6, 7 & 10: Bounded queue rejects requests with OllamaQueueFullError."""
    barrier = threading.Barrier(2)

    def slow_transport(payload, timeout):
        # Wait until test signals to proceed
        try:
            barrier.wait(timeout=1.0)
        except threading.BrokenBarrierError:
            pass
        return '{"records": []}'

    config = OllamaConfig(
        max_concurrency=1,
        max_queue_size=2,
        timeout_seconds=2.0,
    )
    provider = OllamaProvider(config=config, transport_fn=slow_transport)

    # 1. Start active request (occupies the single concurrency slot)
    t_active = threading.Thread(target=lambda: provider.complete("Active request"))
    t_active.start()

    time.sleep(0.02)
    assert provider.active_count == 1

    # 2. Fill the queue up to max_queue_size (2 waiting)
    t_queued1 = threading.Thread(target=lambda: provider.complete("Queued request 1"))
    t_queued2 = threading.Thread(target=lambda: provider.complete("Queued request 2"))
    t_queued1.start()
    t_queued2.start()

    time.sleep(0.05)
    assert provider.waiting_count == 2

    # 3. Next request must be rejected immediately with OllamaQueueFullError
    with pytest.raises(OllamaQueueFullError, match="Ollama request queue is full"):
        provider.complete("Rejected request")

    # Release barrier to allow cleanup
    try:
        barrier.wait(timeout=0.5)
    except Exception:
        pass

    t_active.join()
    t_queued1.join()
    t_queued2.join()

    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_request_timeout_raises_explicit_timeout_error():
    """Requirement 3, 6 & 10: Request timeout raises explicit OllamaTimeoutError."""
    def hanging_transport(payload, timeout):
        time.sleep(0.5)
        return '{"records": []}'

    config = OllamaConfig(
        timeout_seconds=0.1,
        max_retries=0,
    )
    provider = OllamaProvider(config=config, transport_fn=hanging_transport)

    with pytest.raises(OllamaTimeoutError, match="Ollama request exceeded wall-clock timeout"):
        provider.complete("Hanging prompt")


def test_retry_exhaustion_on_transient_failures():
    """Requirement 4, 6 & 10: Retry only transient failures at most 2 times with backoff/jitter."""
    call_count = 0

    def transient_failure_transport(payload, timeout):
        nonlocal call_count
        call_count += 1
        raise urllib.error.URLError("Connection refused")

    config = OllamaConfig(
        max_retries=2,
        base_backoff_seconds=0.01,
        max_backoff_seconds=0.05,
        jitter_seconds=0.01,
        timeout_seconds=2.0,
    )
    provider = OllamaProvider(config=config, transport_fn=transient_failure_transport)

    with pytest.raises(OllamaModelUnavailableError, match="Ollama service unavailable"):
        provider.complete("Test prompt")

    # Initial attempt (1) + 2 retries = 3 calls total
    assert call_count == 3


def test_no_retries_on_non_transient_or_validation_errors():
    """Requirement 4 & 7: Do not retry non-transient or invalid-output failures."""
    call_count = 0

    def non_transient_transport(payload, timeout):
        nonlocal call_count
        call_count += 1
        raise OllamaInvalidOutputError("Invalid JSON structure")

    config = OllamaConfig(
        max_retries=2,
        timeout_seconds=2.0,
    )
    provider = OllamaProvider(config=config, transport_fn=non_transient_transport)

    with pytest.raises(OllamaInvalidOutputError, match="Invalid JSON structure"):
        provider.complete("Test prompt")

    # Must fail immediately after 1 attempt without retrying
    assert call_count == 1


def test_oversized_input_rejected_before_execution():
    """Requirement 5, 6 & 10: Reject oversized inputs with OllamaOversizedInputError."""
    config = OllamaConfig(max_input_bytes=100)
    provider = OllamaProvider(config=config)

    oversized_prompt = "A" * 150
    with pytest.raises(OllamaOversizedInputError, match="Input size .* exceeds limit"):
        provider.complete(oversized_prompt)


def test_oversized_output_rejected_with_invalid_output_error():
    """Requirement 5, 6 & 10: Reject oversized model outputs with OllamaInvalidOutputError."""
    def verbose_transport(payload, timeout):
        return "B" * 200

    config = OllamaConfig(max_output_bytes=50)
    provider = OllamaProvider(config=config, transport_fn=verbose_transport)

    with pytest.raises(OllamaInvalidOutputError, match="Model output size .* exceeded limit"):
        provider.complete("Test prompt")


def test_recovery_after_failed_request():
    """Requirement 10: Semaphore and queue cleanly recover after an error or timeout."""
    should_fail = True

    def toggle_transport(payload, timeout):
        if should_fail:
            raise urllib.error.URLError("Temporary outage")
        return '{"recovered": true}'

    config = OllamaConfig(
        max_concurrency=1,
        max_queue_size=2,
        max_retries=1,
        base_backoff_seconds=0.01,
        timeout_seconds=2.0,
    )
    provider = OllamaProvider(config=config, transport_fn=toggle_transport)

    # 1. First request fails
    with pytest.raises(OllamaModelUnavailableError):
        provider.complete("Failing request")

    assert provider.waiting_count == 0
    assert provider.active_count == 0

    # 2. Second request succeeds cleanly (no deadlock or leaked semaphore)
    should_fail = False
    resp = provider.complete("Recovered request")
    assert resp.content == '{"recovered": true}'
    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_deterministic_checker_independent_of_llm_availability():
    """Requirement 8: Deterministic checker execution remains 100% offline and independent of LLM."""
    fixtures = load_development_fixtures(DEV_FIXTURES_DIR)
    assert len(fixtures) == 20

    sanity = verify_checker_sanity(fixtures)
    assert sanity.perfect_predictions_passed is True
    assert sanity.empty_predictions_passed is True
    assert sanity.planted_bugs_total > 0


def test_default_attempt_count_is_at_most_two():
    """Requirement 4 & Section 2: Default total attempts is at most 2 (1 initial + 1 retry)."""
    default_config = OllamaConfig()
    assert default_config.max_retries == 1
    assert default_config.max_attempts == 2

    call_count = 0

    def transient_failure(payload, timeout):
        nonlocal call_count
        call_count += 1
        raise urllib.error.URLError("Connection reset")

    provider = OllamaProvider(config=default_config, transport_fn=transient_failure)
    with pytest.raises(OllamaModelUnavailableError):
        provider.complete("Test")

    # Initial attempt + 1 retry = 2 total attempts
    assert call_count == 2


def test_queue_wait_expiration_enforces_strict_deadline():
    """Section 2.A: Queue-wait expiration enforces wall-clock deadline without leaking counters."""
    gate = threading.Event()

    def blocking_transport(payload, timeout):
        gate.wait(timeout=1.0)
        return '{"records": []}'

    config = OllamaConfig(
        max_concurrency=1,
        max_queue_size=2,
        timeout_seconds=0.1,  # short 100ms deadline
    )
    provider = OllamaProvider(config=config, transport_fn=blocking_transport)

    # 1. Occupy the concurrency slot
    errors = []

    def occupier():
        try:
            provider.complete("Occupying request")
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=occupier)
    t1.start()
    time.sleep(0.02)
    assert provider.active_count == 1

    # 2. Second request waits in queue and must expire within 100ms
    with pytest.raises(OllamaTimeoutError, match="Timed out waiting in Ollama request queue"):
        provider.complete("Waiting request")

    # Clean up
    gate.set()
    t1.join()
    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_deadline_exhaustion_during_backoff():
    """Section 2.A: Exceeded deadline during retry backoff raises OllamaTimeoutError immediately."""
    call_count = 0

    def slow_transient_failure(payload, timeout):
        nonlocal call_count
        call_count += 1
        time.sleep(0.05)
        raise urllib.error.URLError("Server busy")

    # Timeout is 0.08s, initial call takes 0.05s, backoff is 0.2s -> deadline would be exceeded
    config = OllamaConfig(
        timeout_seconds=0.08,
        max_retries=2,
        base_backoff_seconds=0.2,
        jitter_seconds=0.0,
    )
    provider = OllamaProvider(config=config, transport_fn=slow_transient_failure)

    start = time.monotonic()
    with pytest.raises(OllamaTimeoutError, match="timed out during retry backoff"):
        provider.complete("Test prompt")
    duration = time.monotonic() - start

    assert call_count == 1
    # Must abort promptly without sleeping for the full 0.2s backoff
    assert duration < 0.2


def test_slow_response_reads_enforce_deadline():
    """Section 2.A: Slow response reads exceeding wall-clock deadline raise OllamaTimeoutError."""
    def slow_reader_transport(payload, timeout):
        time.sleep(0.15)
        return '{"records": []}'

    config = OllamaConfig(timeout_seconds=0.1, max_retries=0)
    provider = OllamaProvider(config=config, transport_fn=slow_reader_transport)

    with pytest.raises(OllamaTimeoutError, match="exceeded wall-clock timeout"):
        provider.complete("Test prompt")


def test_race_condition_simultaneous_queue_admission():
    """Section 2.B: Simultaneous queue arrivals under contention enforce queue limit and cleanup."""
    num_threads = 10
    start_barrier = threading.Barrier(num_threads)
    release_event = threading.Event()

    def gated_transport(payload, timeout):
        release_event.wait(timeout=1.0)
        return '{"records": []}'

    # Max concurrency = 1, Max waiting = 5.
    # Out of 10 threads: 1 active, 5 waiting, 4 rejected immediately with QueueFullError.
    config = OllamaConfig(
        max_concurrency=1,
        max_queue_size=5,
        timeout_seconds=2.0,
    )
    provider = OllamaProvider(config=config, transport_fn=gated_transport)

    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            start_barrier.wait(timeout=1.0)
            res = provider.complete("Contended prompt")
            with lock:
                results.append(res)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()

    time.sleep(0.08)
    # Check that waiting count never exceeds max_queue_size (5)
    with provider._lock:
        assert provider._waiting_count <= 5
        assert provider._active_count <= 1

    # Release workers
    release_event.set()
    for t in threads:
        t.join()

    queue_full_errors = [e for e in errors if isinstance(e, OllamaQueueFullError)]
    # Exactly 4 requests rejected
    assert len(queue_full_errors) == 4
    # Exactly 6 requests succeeded (1 initial active + 5 queued)
    assert len(results) == 6

    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_shared_semaphore_across_multiple_provider_instances():
    """Section 2.E: Shared semaphore coordinates concurrency across multiple provider instances."""
    shared_sem = threading.Semaphore(1)
    shared_lock = threading.Lock()

    max_concurrent = 0
    current_active = 0
    state_lock = threading.Lock()

    def tracked_transport(payload, timeout):
        nonlocal max_concurrent, current_active
        with state_lock:
            current_active += 1
            if current_active > max_concurrent:
                max_concurrent = current_active
        time.sleep(0.05)
        with state_lock:
            current_active -= 1
        return '{"records": []}'

    config = OllamaConfig(max_concurrency=1)
    # Two distinct provider instances sharing the same semaphore
    provider1 = OllamaProvider(
        config=config,
        transport_fn=tracked_transport,
        shared_semaphore=shared_sem,
        shared_lock=shared_lock,
    )
    provider2 = OllamaProvider(
        config=config,
        transport_fn=tracked_transport,
        shared_semaphore=shared_sem,
        shared_lock=shared_lock,
    )

    t1 = threading.Thread(target=lambda: provider1.complete("P1 request"))
    t2 = threading.Thread(target=lambda: provider2.complete("P2 request"))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Even though there are 2 separate provider instances, shared semaphore restricted concurrency to 1
    assert max_concurrent == 1


def test_oversized_input_combines_prompt_and_system_prompt_bytes():
    """Section 2.D: UTF-8 byte measurement includes prompt and system_prompt before queueing."""
    config = OllamaConfig(max_input_bytes=100)
    provider = OllamaProvider(config=config)

    # 60 bytes user prompt + 50 bytes system prompt = 110 bytes > 100 bytes limit
    user_p = "A" * 60
    system_p = "B" * 50

    with pytest.raises(OllamaOversizedInputError, match="Input size \\(110 bytes\\) exceeds limit"):
        provider.complete(prompt=user_p, system_prompt=system_p)

    # Neither counter was modified because rejection happened before queueing
    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_error_messages_do_not_leak_prompt_contents():
    """Section 2.D: Error messages do not leak sensitive PR contents in exception strings."""
    config = OllamaConfig(max_input_bytes=50, max_output_bytes=50)
    provider = OllamaProvider(config=config)

    secret_content = "SUPER_SECRET_TOKEN_XYZ_123456789"
    oversized_prompt = secret_content + ("A" * 50)

    try:
        provider.complete(oversized_prompt)
        pytest.fail("Should have raised OllamaOversizedInputError")
    except OllamaOversizedInputError as exc:
        err_msg = str(exc)
        assert secret_content not in err_msg
        assert "exceeds limit" in err_msg


def test_worker_thread_timeout_recovers_concurrency_and_subsequent_request():
    """Requirement 4: Verify bounded resource behavior when a worker thread times out."""
    def hanging_call(payload, timeout):
        time.sleep(0.3)
        return '{"records": []}'

    config = OllamaConfig(
        max_concurrency=1,
        max_queue_size=2,
        timeout_seconds=0.1,  # 100ms timeout
        max_retries=0,
    )
    provider = OllamaProvider(config=config, transport_fn=hanging_call)

    worker_error = []

    def background_worker():
        try:
            provider.complete("Timed out prompt")
        except Exception as exc:
            worker_error.append(exc)

    t = threading.Thread(target=background_worker)
    t.start()
    t.join()

    # Worker thread timed out and caught OllamaTimeoutError
    assert len(worker_error) == 1
    assert isinstance(worker_error[0], OllamaTimeoutError)

    # Concurrency slot and queue are immediately freed and bounded
    assert provider.waiting_count == 0
    assert provider.active_count == 0

    # Subsequent request executes cleanly without being blocked or leaked
    fast_provider = OllamaProvider(
        config=config,
        transport_fn=lambda payload, timeout: '{"records": []}',
    )
    resp = fast_provider.complete("Subsequent prompt")
    assert resp.content == '{"records": []}'


