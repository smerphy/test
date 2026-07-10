"""Auto-resolve, acknowledge, Prometheus exposition."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import (
    AlertAggregation,
    AlertChannel,
    AlertComparison,
    AlertEvent,
    AlertMetric,
    AlertRule,
    AlertState,
    MetricEvent,
    Organization,
)
from app.services.alerts import evaluate_rule


def _past_base() -> datetime:
    return datetime.now(UTC) - timedelta(minutes=1)


def _add_metric(
    session: Session,
    org: Organization,
    *,
    base: datetime,
    n: int,
    cost_usd: float = 0.05,
    model: str = "claude-opus-4-7",
    status: str = "success",
) -> None:
    for i in range(n):
        session.add(
            MetricEvent(
                organization_id=org.id,
                timestamp=base + timedelta(seconds=i),
                agent_id="a",
                model=model,
                operation="messages.create",
                duration_ms=100,
                input_tokens=10,
                output_tokens=10,
                cache_read_tokens=0,
                cache_write_tokens=0,
                cost_usd=cost_usd,
                status=status,
                tools_used=[],
            )
        )
    session.commit()


def _rule(org: Organization, **overrides) -> AlertRule:
    base = dict(
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
    base.update(overrides)
    return AlertRule(**base)


def _mock_ok():
    from unittest.mock import MagicMock

    import httpx

    client = MagicMock(spec=httpx.Client)
    resp = MagicMock(spec=httpx.Response)
    resp.raise_for_status.return_value = None
    client.post.return_value = resp
    return client


class TestAutoResolve:
    def test_resolves_when_metric_drops_below_threshold(
        self, session: Session, org: Organization
    ) -> None:
        # First, seed enough cost to trigger and fire.
        _add_metric(session, org, base=_past_base(), n=20, cost_usd=0.05)
        rule = _rule(org)
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_ok())
        assert len(fired) == 1
        assert fired[0].state is AlertState.FIRING

        # Now clear the metrics so the next eval has 0 cost in window.
        session.query(MetricEvent).delete()
        session.commit()

        evaluate_rule(session, rule, http_client=_mock_ok())

        # The original firing should now be RESOLVED.
        refreshed = session.get(AlertEvent, fired[0].id)
        assert refreshed is not None
        assert refreshed.state is AlertState.RESOLVED
        assert refreshed.resolved_at is not None


class TestAcknowledge:
    def test_acknowledge_firing(
        self,
        client: TestClient,
        session: Session,
        org: Organization,
    ) -> None:
        _add_metric(session, org, base=_past_base(), n=20)
        rule = _rule(org)
        session.add(rule)
        session.commit()
        fired = evaluate_rule(session, rule, http_client=_mock_ok())
        assert fired

        r = client.post(
            f"/alerts/events/{fired[0].id}/acknowledge",
            json={"acknowledged_by": "alice@acme", "note": "looking now"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["state"] == "acknowledged"
        assert body["acknowledged_by"] == "alice@acme"
        assert body["acknowledged_at"] is not None

    def test_acknowledge_unknown_returns_404(self, client: TestClient) -> None:
        r = client.post(
            "/alerts/events/missing/acknowledge",
            json={"acknowledged_by": "x"},
        )
        assert r.status_code == 404

    def test_cannot_acknowledge_resolved_event(
        self,
        client: TestClient,
        session: Session,
        org: Organization,
    ) -> None:
        ev = AlertEvent(
            organization_id=org.id,
            rule_id="placeholder",
            fired_at=datetime.now(UTC),
            state=AlertState.RESOLVED,
            metric_value=1.0,
            threshold=0.5,
        )
        session.add(ev)
        session.commit()
        r = client.post(
            f"/alerts/events/{ev.id}/acknowledge",
            json={"acknowledged_by": "x"},
        )
        assert r.status_code == 409


class TestPrometheus:
    def test_exposition_contains_expected_series(
        self, client: TestClient, session: Session, org: Organization
    ) -> None:
        _add_metric(session, org, base=_past_base(), n=5, cost_usd=0.10)
        _add_metric(
            session,
            org,
            base=_past_base(),
            n=2,
            model="claude-haiku-4-5",
            cost_usd=0.01,
        )
        # Plus one error.
        _add_metric(session, org, base=_past_base(), n=1, status="error")

        r = client.get("/metrics/prometheus")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        body = r.text
        assert "ephorate_requests_total" in body
        assert "ephorate_tokens_total" in body
        assert "ephorate_cost_usd_total" in body
        assert "ephorate_request_duration_ms_summary" in body
        assert 'model="claude-opus-4-7"' in body
        assert 'model="claude-haiku-4-5"' in body
        assert 'status="error"' in body
        # Help + type lines present (Prometheus format compliance).
        assert "# HELP ephorate_requests_total" in body
        assert "# TYPE ephorate_requests_total counter" in body

    def test_exposition_quantile_labels(
        self, client: TestClient, session: Session, org: Organization
    ) -> None:
        _add_metric(session, org, base=_past_base(), n=20)
        body = client.get("/metrics/prometheus").text
        assert 'quantile="0.5"' in body
        assert 'quantile="0.95"' in body
        assert 'quantile="0.99"' in body
