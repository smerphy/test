"""Kafka/Redpanda backend for :class:`~app.services.eventlog.EventLog`.

The production swap for the SQL log at high volume. Same three-method contract
(``append`` / ``poll`` / ``commit``), so nothing downstream changes — only
``EPHORATE_LOG_BACKEND=kafka`` + ``EPHORATE_KAFKA_BOOTSTRAP_SERVERS``.

``confluent-kafka`` is an optional dependency: it is imported lazily so the
control plane runs (and CI passes) without it. Partitioning is by
``partition_key`` (org:agent:session), which Kafka hashes to a partition,
preserving per-chain arrival order the same way the SQL log's monotonic id
does. Offsets are Kafka consumer-group offsets; ``poll`` commits are manual so
delivery stays at-least-once and downstream materializers must be idempotent.

This adapter is intentionally not exercised in CI (no broker); it is validated
against a real Kafka/Redpanda in staging.
"""

from __future__ import annotations

from typing import Any

from app.services.eventlog import LoggedRecord, Record


class KafkaEventLog:
    """EventLog over Kafka/Redpanda. Requires confluent-kafka + a broker."""

    def __init__(self) -> None:  # pragma: no cover - needs a broker
        from app.settings import get_settings

        settings = get_settings()
        if not settings.kafka_bootstrap_servers:
            raise RuntimeError(
                "log_backend=kafka requires EPHORATE_KAFKA_BOOTSTRAP_SERVERS"
            )
        self._servers = settings.kafka_bootstrap_servers
        self._prefix = settings.kafka_topic_prefix
        self._producer: Any = None
        self._consumers: dict[str, Any] = {}

    def _topic(self, topic: str) -> str:  # pragma: no cover
        return f"{self._prefix}{topic}"

    def _get_producer(self) -> Any:  # pragma: no cover - needs a broker
        if self._producer is None:
            from confluent_kafka import Producer

            self._producer = Producer({"bootstrap.servers": self._servers})
        return self._producer

    def append(
        self, topic: str, org_id: str, partition_key: str, records: list[Record]
    ) -> int:  # pragma: no cover - needs a broker
        import json

        producer = self._get_producer()
        for rec in records:
            producer.produce(
                self._topic(topic),
                key=partition_key,
                value=json.dumps({"org": org_id, "payload": rec}),
            )
        producer.flush()
        return len(records)

    def _get_consumer(self, group: str) -> Any:  # pragma: no cover
        consumer = self._consumers.get(group)
        if consumer is None:
            from confluent_kafka import Consumer

            consumer = Consumer(
                {
                    "bootstrap.servers": self._servers,
                    "group.id": group,
                    "enable.auto.commit": False,
                    "auto.offset.reset": "earliest",
                }
            )
            self._consumers[group] = consumer
        return consumer

    def poll(
        self, topic: str, consumer_group: str, max_records: int = 500
    ) -> list[LoggedRecord]:  # pragma: no cover - needs a broker
        import json

        consumer = self._get_consumer(consumer_group)
        consumer.subscribe([self._topic(topic)])
        out: list[LoggedRecord] = []
        for _ in range(max_records):
            msg = consumer.poll(timeout=0.5)
            if msg is None or msg.error():
                break
            envelope: dict[str, Any] = json.loads(msg.value())
            out.append(
                LoggedRecord(
                    offset=msg.offset(),
                    organization_id=envelope.get("org", ""),
                    partition_key=(msg.key() or b"").decode(),
                    payload=envelope.get("payload", {}),
                )
            )
        return out

    def commit(
        self, topic: str, consumer_group: str, offset: int
    ) -> None:  # pragma: no cover - needs a broker
        consumer = self._consumers.get(consumer_group)
        if consumer is not None:
            consumer.commit(asynchronous=False)

    def lag(self, topic: str, consumer_group: str) -> int:  # pragma: no cover
        # Broker-side lag is read via the admin API in production dashboards;
        # not needed for the drain loop.
        return 0


__all__ = ["KafkaEventLog"]
