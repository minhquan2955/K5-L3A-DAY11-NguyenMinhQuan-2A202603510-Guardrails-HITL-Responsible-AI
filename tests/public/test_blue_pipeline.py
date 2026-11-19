import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

from google.genai import types

from assignment.pipeline import build_observability, build_production_plugins, is_egress_allowed, run_assignment_suite
from assignment.rate_limiter import RateLimitPlugin
from core.openai_runtime import OpenAIRunner


def test_rate_limit_is_per_user_and_expires_at_window_boundary(monkeypatch):
    clock = 100.0
    monkeypatch.setattr("assignment.rate_limiter.monotonic", lambda: clock)
    limiter = RateLimitPlugin(max_requests=1, window_seconds=60)
    message = types.Content(parts=[types.Part.from_text(text="What is my account balance?")])

    async def send(user_id):
        return await limiter.on_user_message_callback(
            invocation_context=SimpleNamespace(user_id=user_id), user_message=message,
        )

    assert asyncio.run(send("a")) is None
    assert asyncio.run(send("a")) is not None
    assert asyncio.run(send("b")) is None
    clock = 160.0
    assert asyncio.run(send("a")) is None
    assert (limiter.total_count, limiter.blocked_count) == (4, 1)


def test_egress_rejects_contact_data_and_requires_exact_https_destination():
    assert is_egress_allowed("https://cases.vinbank.example/v1", "approved case summary")
    assert not is_egress_allowed("https://cases.vinbank.example/v1", "customer@example.com")
    assert not is_egress_allowed("https://api.vinbank.example.evil.example/v1", "approved case summary")
    assert not is_egress_allowed("https://api.vinbank.example:invalid/v1", "approved case summary")


def test_egress_rejects_labeled_credentials_outside_demo_fixture():
    destination = "https://api.vinbank.example/v1"
    assert not is_egress_allowed(destination, 'config: {"api_key": "ExampleToken"}')
    assert not is_egress_allowed(destination, "database host is storage.example")
    assert not is_egress_allowed(destination, "password is ExampleWord")


def test_suite_records_decisions_and_exports_files(monkeypatch, tmp_path):
    completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="Contact customer@example.com"))],
    )
    create = Mock(return_value=completion)
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(OpenAIRunner, "_client", lambda self: client)
    audit, monitor = build_observability()
    pipeline = {
        "plugins": build_production_plugins(),
        "audit": audit,
        "monitor": monitor,
        "output_dir": tmp_path,
    }

    results = asyncio.run(run_assignment_suite(pipeline))
    assert results == json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert all(not case["blocked"] and "[REDACTED]" in case["response_preview"] for case in results["safe_queries"])
    assert sum(case["blocked"] for case in results["attack_queries"]) >= 5
    assert results["rate_limit"]["blocked"] == 5
    assert create.call_count >= len(results["safe_queries"])

    logs = json.loads((tmp_path / "audit_log.json").read_text(encoding="utf-8"))
    metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert len(logs) == metrics["total_requests"]
    assert sum(row["blocked"] for row in logs) == metrics["blocked_requests"]
    assert metrics["rate_limit_hits"] == 5
    assert any(alert["metric"] == "block_rate" for alert in metrics["alerts"])
    assert all(row["latency_ms"] >= 0 for row in logs)
    assert "customer@example.com" not in json.dumps(logs)
