"""Deterministic regression tests for Ollama concurrency, timeout lifecycle, and HTTP socket behavior.

Covers Phase 2 requirements using a controllable fake HTTP server:
1. Normal response lifecycle.
2. Request that blocks past caller deadline (hard socket timeout & cleanup).
3. Multiple simultaneous callers proving that max actual in-flight HTTP requests == max_concurrency.
4. Queue saturation fast-rejection.
5. Retry after transient failure with strict sequential execution (no overlapping retries).
6. Repeated timeouts bounding execution.
7. Graceful provider shutdown while requests are active/queued.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Tuple
import pytest

from src.detection.ollama_provider import (
    OllamaConfig,
    OllamaError,
    OllamaProvider,
    OllamaQueueFullError,
    OllamaTimeoutError,
)


class ControllableHTTPHandler(BaseHTTPRequestHandler):
    """Controllable test double HTTP handler with synchronization primitives."""

    # Class-level shared state configured by tests
    delay_seconds: float = 0.0
    block_event: threading.Event = None
    response_sequence: List[Tuple[int, str]] = []
    active_requests: int = 0
    max_active_requests: int = 0
    request_lock = threading.Lock()
    request_log: List[dict] = []

    @classmethod
    def reset_state(cls) -> None:
        with cls.request_lock:
            cls.delay_seconds = 0.0
            cls.block_event = None
            cls.response_sequence = []
            cls.active_requests = 0
            cls.max_active_requests = 0
            cls.request_log = []

    def log_message(self, format: str, *args: object) -> None:
        """Suppress default stderr logging during tests."""
        pass

    def do_POST(self) -> None:
        arrival_time = time.monotonic()
        with self.request_lock:
            ControllableHTTPHandler.active_requests += 1
            if ControllableHTTPHandler.active_requests > ControllableHTTPHandler.max_active_requests:
                ControllableHTTPHandler.max_active_requests = ControllableHTTPHandler.active_requests

        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b""
            body_json = {}
            if body_bytes:
                try:
                    body_json = json.loads(body_bytes.decode("utf-8"))
                except Exception:
                    pass

            # Optional blocking event for deadline testing
            if ControllableHTTPHandler.block_event is not None:
                ControllableHTTPHandler.block_event.wait(timeout=2.0)

            # Optional fixed delay
            if ControllableHTTPHandler.delay_seconds > 0:
                time.sleep(ControllableHTTPHandler.delay_seconds)

            # Determine response status and body
            status_code = 200
            resp_payload = {"response": "controlled test response"}

            with self.request_lock:
                if ControllableHTTPHandler.response_sequence:
                    status_code, resp_text = ControllableHTTPHandler.response_sequence.pop(0)
                    if status_code == 200:
                        resp_payload = {"response": resp_text}
                    else:
                        resp_payload = {"error": resp_text}

            try:
                resp_data = json.dumps(resp_payload).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_data)))
                self.end_headers()
                self.wfile.write(resp_data)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
                pass
        finally:
            finish_time = time.monotonic()
            with self.request_lock:
                ControllableHTTPHandler.active_requests = max(0, ControllableHTTPHandler.active_requests - 1)
                ControllableHTTPHandler.request_log.append({
                    "arrival": arrival_time,
                    "finish": finish_time,
                    "body": body_json,
                })


@pytest.fixture
def fake_http_server():
    """Start an ephemeral ThreadingHTTPServer on 127.0.0.1 with ControllableHTTPHandler."""
    ControllableHTTPHandler.reset_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), ControllableHTTPHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url

    server.shutdown()
    server.server_close()
    server_thread.join(timeout=2.0)
    ControllableHTTPHandler.reset_state()


def test_lifecycle_1_normal_response(fake_http_server: str) -> None:
    """1. Normal HTTP request lifecycle succeeds and leaves zero resource leaks."""
    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        timeout_seconds=5.0,
    )
    provider = OllamaProvider(config=config)

    resp = provider.complete("Analyze security diff")
    assert resp.content == "controlled test response"
    assert resp.metadata.provider_name == "ollama"
    assert resp.metadata.extra_config["attempts_used"] == 1
    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_lifecycle_2_request_blocks_past_caller_deadline(fake_http_server: str) -> None:
    """2. Request blocking past deadline unblocks caller with OllamaTimeoutError and restores semaphore."""
    # Configure handler to block until block_event is set
    block_evt = threading.Event()
    ControllableHTTPHandler.block_event = block_evt

    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        timeout_seconds=0.4,
        max_retries=0,
    )
    provider = OllamaProvider(config=config)

    with pytest.raises(OllamaTimeoutError):
        provider.complete("Hanging prompt")

    # Release server thread
    block_evt.set()

    # Verify concurrency controls are cleanly released
    assert provider.waiting_count == 0
    assert provider.active_count == 0

    # Ensure subsequent request immediately succeeds
    ControllableHTTPHandler.reset_state()
    subsequent_resp = provider.complete("Subsequent prompt")
    assert subsequent_resp.content == "controlled test response"


def test_lifecycle_3_multiple_simultaneous_callers_enforce_actual_inflight_limit(
    fake_http_server: str,
) -> None:
    """3. Verify semaphore restricts actual in-flight HTTP requests reaching Ollama to max_concurrency."""
    # Delay each request by 0.08s so multiple requests overlap if not bounded
    ControllableHTTPHandler.delay_seconds = 0.08

    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        max_concurrency=1,
        max_queue_size=10,
        timeout_seconds=10.0,
    )
    provider = OllamaProvider(config=config)

    results: List[str] = []
    errors: List[Exception] = []
    threads: List[threading.Thread] = []

    def caller_worker(idx: int) -> None:
        try:
            r = provider.complete(f"Prompt {idx}")
            results.append(r.content)
        except Exception as e:
            errors.append(e)

    for i in range(4):
        t = threading.Thread(target=caller_worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0
    assert len(results) == 4
    # Crucial proof: The server must NEVER have observed more than max_concurrency (1) in flight!
    assert ControllableHTTPHandler.max_active_requests == 1
    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_lifecycle_4_queue_saturation_rejects_excess_callers(fake_http_server: str) -> None:
    """4. Bounded waiting queue fast-fails excess callers when saturated without touching network."""
    block_evt = threading.Event()
    ControllableHTTPHandler.block_event = block_evt

    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        max_concurrency=1,
        max_queue_size=2,
        timeout_seconds=5.0,
    )
    provider = OllamaProvider(config=config)

    # 1. Thread holds active slot
    t_active = threading.Thread(target=lambda: provider.complete("Active"))
    t_active.start()
    time.sleep(0.05)

    # 2. Threads fill wait queue (max 2)
    t_q1 = threading.Thread(target=lambda: provider.complete("Queued 1"))
    t_q2 = threading.Thread(target=lambda: provider.complete("Queued 2"))
    t_q1.start()
    t_q2.start()
    time.sleep(0.05)

    assert provider.waiting_count == 2

    # 3. 4th caller exceeds max_queue_size -> must raise OllamaQueueFullError immediately
    with pytest.raises(OllamaQueueFullError, match="Ollama request queue is full"):
        provider.complete("Rejected 4th request")

    # Unblock and join
    block_evt.set()
    t_active.join(timeout=3.0)
    t_q1.join(timeout=3.0)
    t_q2.join(timeout=3.0)

    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_lifecycle_5_retry_after_transient_failure_never_overlaps(fake_http_server: str) -> None:
    """5. Transient 503 error triggers retry with strict serialized execution (no duplicate in-flight requests)."""
    ControllableHTTPHandler.response_sequence = [
        (503, "Service Unavailable (temporarily overloaded)"),
        (200, "Recovered successfully on retry"),
    ]

    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        max_retries=1,
        base_backoff_seconds=0.05,
        timeout_seconds=5.0,
    )
    provider = OllamaProvider(config=config)

    resp = provider.complete("Retry prompt")
    assert resp.content == "Recovered successfully on retry"
    assert resp.metadata.extra_config["attempts_used"] == 2

    # Check server log: attempt 1 must have completely finished before attempt 2 arrived
    log = ControllableHTTPHandler.request_log
    assert len(log) == 2
    assert log[1]["arrival"] >= log[0]["finish"]
    assert ControllableHTTPHandler.max_active_requests == 1


def test_lifecycle_6_repeated_timeouts_bounded(fake_http_server: str) -> None:
    """6. Repeated socket read timeouts exhaust deadline and raise OllamaTimeoutError cleanly."""
    block_evt = threading.Event()
    ControllableHTTPHandler.block_event = block_evt

    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        max_retries=1,
        base_backoff_seconds=0.05,
        timeout_seconds=0.4,
    )
    provider = OllamaProvider(config=config)

    with pytest.raises(OllamaTimeoutError):
        provider.complete("Repeated timeout prompt")

    block_evt.set()
    assert provider.waiting_count == 0
    assert provider.active_count == 0


def test_lifecycle_7_shutdown_while_requests_active(fake_http_server: str) -> None:
    """7. Provider shutdown unblocks waiting queue callers immediately and rejects new ones."""
    block_evt = threading.Event()
    ControllableHTTPHandler.block_event = block_evt

    config = OllamaConfig(
        base_url=fake_http_server,
        model_name="qwen2:1.5b",
        max_concurrency=1,
        max_queue_size=5,
        timeout_seconds=10.0,
    )
    provider = OllamaProvider(config=config)

    # 1. Thread 1 is in-flight
    t1 = threading.Thread(target=lambda: provider.complete("In flight"))
    t1.start()
    time.sleep(0.05)

    # 2. Thread 2 is queued waiting for semaphore
    q_errors: List[Exception] = []

    def queued_caller():
        try:
            provider.complete("Queued caller")
        except Exception as e:
            q_errors.append(e)

    t2 = threading.Thread(target=queued_caller)
    t2.start()
    time.sleep(0.05)

    assert provider.waiting_count == 1
    assert not provider.is_closed

    # 3. Trigger provider shutdown
    provider.close()
    assert provider.is_closed

    # Thread 2 should unblock with OllamaError indicating shutdown
    t2.join(timeout=2.0)
    assert len(q_errors) == 1
    assert isinstance(q_errors[0], OllamaError)
    assert "shut down while waiting in queue" in str(q_errors[0])

    # 4. New caller rejected immediately
    with pytest.raises(OllamaError, match="OllamaProvider is closed"):
        provider.complete("New caller after shutdown")

    block_evt.set()
    t1.join(timeout=2.0)
