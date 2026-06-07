from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import MetricEvent


def _ev(**overrides) -> dict:
    base = {
        "timestamp": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC).isoformat(),
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "model": "claude-opus-4-7",
        "operation": "messages.create",
        "request_id": "req_abc",
        "duration_ms": 1200,
        "input_tokens": 1000,
        "output_tokens": 500,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "status": "success",
        "stop_reason": "end_turn",
        "tools_used": [],
        "metadata": {},
    }
    base.update(overrides)
    return base


class TestIngest:
    def test_accepts_well_formed_event(self, client: TestClient) -> None:
        r = client.post("/metrics/events", json=[_ev()])
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 1
        assert body["rejected"] == 0

    def test_computes_cost_when_omitted(
        self, client: TestClient, session: Session
    ) -> None:
        client.post("/metrics/events", json=[_ev()])
        ev = session.execute(
            MetricEvent.__table__.select().limit(1)
        ).first()
        # 1000 input * 15 + 500 output * 75 per million = 0.015 + 0.0375 = 0.0525
        assert ev is not None
        assert abs(ev.cost_usd - 0.0525) < 1e-9

    def test_unknown_model_yields_zero_cost(
        self, client: TestClient, session: Session
    ) -> None:
        client.post("/metrics/events", json=[_ev(model="claude-imaginary")])
        ev = session.execute(MetricEvent.__table__.select().limit(1)).first()
        assert ev is not None
        assert ev.cost_usd == 0.0

    def test_sdk_supplied_cost_is_respected(
        self, client: TestClient, session: Session
    ) -> None:
        client.post(
            "/metrics/events", json=[_ev(cost_usd=42.0, model="claude-imaginary")]
        )
        ev = session.execute(MetricEvent.__table__.select().limit(1)).first()
        assert ev is not None
        assert ev.cost_usd == 42.0


class TestSearch:
    def test_filters_by_model_and_status(self, client: TestClient) -> None:
        client.post(
            "/metrics/events",
            json=[
                _ev(model="claude-opus-4-7", status="success"),
                _ev(model="claude-sonnet-4-6", status="error", error_type="rate_limit"),
                _ev(model="claude-opus-4-7", status="error", error_type="timeout"),
            ],
        )
        opus = client.get("/metrics/events?model=claude-opus-4-7").json()
        assert len(opus) == 2

        errors = client.get("/metrics/events?status=error").json()
        assert len(errors) == 2


class TestAggregate:
    def test_buckets_one_event_per_minute(self, client: TestClient) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        events = [
            _ev(timestamp=(base + timedelta(minutes=i)).isoformat())
            for i in range(10)
        ]
        client.post("/metrics/events", json=events)

        r = client.get(
            "/metrics/aggregate",
            params={
                "bucket_minutes": 5,
                "since": base.isoformat(),
                "until": (base + timedelta(minutes=11)).isoformat(),
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["bucket_size_minutes"] == 5
        # 10 events across 2 buckets of 5 minutes each → 5 per bucket.
        assert len(body["buckets"]) == 2
        assert body["buckets"][0]["request_count"] == 5
        assert body["buckets"][1]["request_count"] == 5
        # 1500 tokens per event x 5 events = 7500 total tokens.
        assert body["buckets"][0]["total_tokens"] == 7500

    def test_groups_by_model(self, client: TestClient) -> None:
        base = datetime(2026, 1, 1, tzinfo=UTC)
        client.post(
            "/metrics/events",
            json=[
                _ev(timestamp=base.isoformat(), model="claude-opus-4-7"),
                _ev(timestamp=base.isoformat(), model="claude-opus-4-7"),
                _ev(timestamp=base.isoformat(), model="claude-haiku-4-5"),
            ],
        )
        r = client.get(
            "/metrics/aggregate",
            params={
                "bucket_minutes": 60,
                "group_by": "model",
                "since": base.isoformat(),
                "until": (base + timedelta(hours=1)).isoformat(),
            },
        )
        body = r.json()
        assert body["group_by"] == "model"
        assert set(body["by_group"]) == {"claude-opus-4-7", "claude-haiku-4-5"}
        assert body["by_group"]["claude-opus-4-7"][0]["request_count"] == 2
        assert body["by_group"]["claude-haiku-4-5"][0]["request_count"] == 1


class TestCostComputation:
    def test_lookup_known_models(self) -> None:
        from app.services.cost import known_models, lookup_pricing

        for m in known_models():
            assert lookup_pricing(m) is not None

    def test_fuzzy_strips_date_suffix(self) -> None:
        from app.services.cost import lookup_pricing

        # `claude-haiku-4-5-20251001` is exact; date stripping handles
        # patterns like `claude-sonnet-4-6-20260101` that aren't pinned.
        assert lookup_pricing("claude-sonnet-4-6-20260101") is not None
