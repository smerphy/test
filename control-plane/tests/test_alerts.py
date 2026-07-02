from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    AlertAggregation,
    AlertChannel,
    AlertComparison,
    AlertMetric,
    AlertRule,
    AlertSeverity,
    MetricEvent,
    Organization,
)
from app.services.alerts import evaluate_rule


def _past_base() -> datetime:
    """A `base` safely in the past so events fall inside the evaluator's
    `[now-window, now)` window."""
    return datetime.now(UTC) - timedelta(minutes=1)


def _seed_metrics(
    session: Session,
    org: Organization,
    *,
    base: datetime,
    n: int,
    model: str = "claude-opus-4-7",
    status: str = "success",
    input_tokens: int = 1000,
    output_tokens: int = 500,
    duration_ms: int = 1200,
    cost_usd: float = 0.05,
) -> None:
    for i in range(n):
        session.add(
            MetricEvent(
                organization_id=org.id,
                timestamp=base + timedelta(seconds=i),
                agent_id="a",
                model=model,
                operation="messages.create",
                duration_ms=duration_ms,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=cost_usd,
                status=status,
                tools_used=[],
            )
        )
    session.commit()


class TestRuleCrud:
    def test_create_and_list(self, client: TestClient) -> None:
        payload = {
            "name": "high cost",
            "metric": "cost_usd",
            "aggregation": "sum",
            "window_minutes": 15,
            "threshold": 10.0,
            "comparison": "gt",
            "channel": "webhook",
            "target": "https://example.com/hook",
        }
        r = client.post("/alerts/rules", json=payload)
        assert r.status_code == 201
        rid = r.json()["id"]
        assert any(row["id"] == rid for row in client.get("/alerts/rules").json())


class TestEvaluator:
    def test_sum_cost_above_threshold_fires(
        self, client: TestClient, session: Session, org: Organization
    ) -> None:
        # 20 events x $0.05 each = $1.00 total in last 15 minutes.
        _seed_metrics(
            session, org, base=_past_base(), n=20
        )
        rule = AlertRule(
            organization_id=org.id,
            name="cost",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=0.5,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
        )
        session.add(rule)
        session.commit()

        fired = evaluate_rule(
            session, rule, http_client=_mock_http(202)
        )
        assert len(fired) == 1
        assert fired[0].metric_value == pytest.approx(1.0)
        assert fired[0].delivered is True

    def test_below_threshold_does_not_fire(
        self, session: Session, org: Organization
    ) -> None:
        _seed_metrics(
            session, org, base=_past_base(), n=2
        )
        rule = AlertRule(
            organization_id=org.id,
            name="cost",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=10.0,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
        )
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert fired == []

    def test_p99_duration(self, session: Session, org: Organization) -> None:
        now = _past_base()
        for ms in [100, 150, 200, 300, 500, 800, 1000, 1500, 2000, 5000]:
            session.add(
                MetricEvent(
                    organization_id=org.id,
                    timestamp=now,
                    agent_id="a",
                    model="claude-opus-4-7",
                    duration_ms=ms,
                    input_tokens=0,
                    output_tokens=0,
                    cache_read_tokens=0,
                    cache_write_tokens=0,
                    cost_usd=0.0,
                    status="success",
                    tools_used=[],
                )
            )
        session.commit()
        rule = AlertRule(
            organization_id=org.id,
            name="latency",
            metric=AlertMetric.DURATION_MS,
            aggregation=AlertAggregation.P99,
            window_minutes=15,
            threshold=4000,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
        )
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert len(fired) == 1
        assert fired[0].metric_value == 5000

    def test_group_by_model_fires_per_group(
        self, session: Session, org: Organization
    ) -> None:
        base = _past_base()
        # opus: 5 events x $0.20 = $1.00 (over threshold $0.50)
        _seed_metrics(
            session, org, base=base, n=5, model="claude-opus-4-7", cost_usd=0.20
        )
        # haiku: 2 events x $0.05 = $0.10 (under threshold)
        _seed_metrics(
            session, org, base=base, n=2, model="claude-haiku-4-5", cost_usd=0.05
        )
        rule = AlertRule(
            organization_id=org.id,
            name="cost per model",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=0.5,
            comparison=AlertComparison.GT,
            group_by="model",
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
        )
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert len(fired) == 1
        assert fired[0].group_key == "claude-opus-4-7"

    def test_error_rate(self, session: Session, org: Organization) -> None:
        base = _past_base()
        _seed_metrics(session, org, base=base, n=8, status="success")
        _seed_metrics(session, org, base=base, n=2, status="error")
        rule = AlertRule(
            organization_id=org.id,
            name="errors",
            metric=AlertMetric.ERROR_RATE,
            aggregation=AlertAggregation.RATE,
            window_minutes=15,
            threshold=0.1,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
        )
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert len(fired) == 1
        assert abs(fired[0].metric_value - 0.2) < 1e-9

    def test_cooldown_suppresses_repeat_firing(
        self, session: Session, org: Organization
    ) -> None:
        _seed_metrics(session, org, base=_past_base(), n=20)
        rule = AlertRule(
            organization_id=org.id,
            name="cost",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=0.5,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=15,
        )
        session.add(rule)
        session.commit()
        fired1 = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert len(fired1) == 1
        fired2 = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert fired2 == []  # cooldown active

    def test_cooldown_is_per_group_not_rule_wide(
        self, session: Session, org: Organization
    ) -> None:
        """A firing in one group must not suppress a first breach in another."""
        base = _past_base()
        # Only opus is over threshold in the first evaluation.
        _seed_metrics(
            session, org, base=base, n=5, model="claude-opus-4-7", cost_usd=0.20
        )
        rule = AlertRule(
            organization_id=org.id,
            name="cost per model",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=0.5,
            comparison=AlertComparison.GT,
            group_by="model",
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=15,
        )
        session.add(rule)
        session.commit()
        fired1 = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert [e.group_key for e in fired1] == ["claude-opus-4-7"]

        # Now haiku crosses the threshold. Opus is still in cooldown, but
        # haiku has never fired and must not be suppressed by opus's firing.
        _seed_metrics(
            session, org, base=base, n=5, model="claude-haiku-4-5", cost_usd=0.20
        )
        fired2 = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert [e.group_key for e in fired2] == ["claude-haiku-4-5"]

    def test_delivery_error_recorded_not_raised(
        self, session: Session, org: Organization
    ) -> None:
        _seed_metrics(session, org, base=_past_base(), n=20)
        rule = AlertRule(
            organization_id=org.id,
            name="cost",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=0.5,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
        )
        session.add(rule)
        session.commit()
        # Simulate a 500 from the webhook target.
        client = _mock_http(500)
        fired = evaluate_rule(session, rule, http_client=client)
        assert len(fired) == 1
        assert fired[0].delivered is False
        assert fired[0].delivery_error is not None

    def test_disabled_rule_skipped(
        self, session: Session, org: Organization
    ) -> None:
        _seed_metrics(session, org, base=_past_base(), n=20)
        rule = AlertRule(
            organization_id=org.id,
            name="cost",
            metric=AlertMetric.COST_USD,
            aggregation=AlertAggregation.SUM,
            window_minutes=15,
            threshold=0.5,
            comparison=AlertComparison.GT,
            channel=AlertChannel.WEBHOOK,
            target="https://example.com/hook",
            cooldown_minutes=0,
            enabled=False,
        )
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_http(202))
        assert fired == []


class TestSlackPayload:
    def test_slack_payload_has_header_and_detail(
        self, session: Session, org: Organization
    ) -> None:
        _seed_metrics(session, org, base=_past_base(), n=20)
        rule = AlertRule(
            organization_id=org.id,
            name="high cost",
            metric="cost_usd",
            aggregation="sum",
            window_minutes=15,
            threshold=0.5,
            comparison="gt",
            channel=AlertChannel.SLACK,
            target="https://hooks.slack.com/services/T0/B0/x",
            cooldown_minutes=0,
            severity=AlertSeverity.CRITICAL,
        )
        session.add(rule)
        session.commit()

        client = _mock_http(200)
        fired = evaluate_rule(session, rule, http_client=client)
        sent = client.post.call_args.kwargs["json"]
        assert sent["text"].startswith("[CRITICAL]")
        assert any(b["type"] == "header" for b in sent["blocks"])
        assert fired[0].payload["slack"]["text"] == sent["text"]


def _mock_http(status_code: int) -> httpx.Client:
    """Returns a MagicMock that quacks like an httpx.Client.post."""
    client = MagicMock(spec=httpx.Client)
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status.return_value = None
    client.post.return_value = resp
    return client
