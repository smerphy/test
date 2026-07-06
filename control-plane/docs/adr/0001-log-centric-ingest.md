# ADR 0001 — Log-centric ingest (durable log + CQRS consumers + OTel tier)

Status: accepted · Applies to: `control-plane`, `sdk-python`

## Context

The original ingest path did three coupled things synchronously, per event, in
one Postgres transaction: **durably accept**, **cryptographically verify the
hash chain**, and **write the analyst query store**. That single Postgres
instance was simultaneously the write sink, the integrity oracle, and the
read/search store — three very different workloads contending for one engine,
with the chain-tip read serializing per chain and capping ingest throughput.

Steps 1–3 removed the cheapest contention (batched shipping, async
verification, authoritative archival). Step 4 addresses the structural limit:
the single writer.

## Decision

Introduce a **durable, partitioned event log as the ingest front** and derive
every store from it (CQRS). Ingest appends to the log and returns; consumer
groups materialize the stores off the request path.

```
 agent SDK ─┐
            ├─▶ (optional) OTel Collector ──OTLP──▶ /otlp/v1/metrics ─┐
 OTLP libs ─┘                                                         │
                                          POST /audit|/metrics events │
                                                                      ▼
                                              ┌──────────  EVENT LOG  ──────────┐
                                              │ topic=audit (part. by agent,ses) │
                                              │ topic=metric (part. by org)      │
                                              └───────┬─────────────────┬────────┘
                                   group=hot-store    │                 │  group=analytics
                                                      ▼                 ▼
                                        Postgres hot store        columnar analytics
                                        (verify + dedup;          (NDJSON / ClickHouse;
                                         analyst/search view)      full-history rollups)
```

Key properties:

- **Partition by `(org, agent, session)`** (audit) / `org` (metric). A
  partition's records keep arrival order, so the per-chain hash linkage the
  hot-store materializer needs is preserved by the log, not by a synchronous
  DB transaction.
- **Consumer groups with independent offsets.** The `hot-store` and
  `analytics` groups read the same log independently; each can lag or be
  replayed without affecting the other. The log fans out to every store.
- **At-least-once + idempotent materializers.** A consumer that crashes after
  processing but before committing reprocesses; the hot store dedups audit
  events on `(org, hash)`, so this is safe. A poison record is skipped, never
  wedging the group.
- **The log is the system of record; the hot store is a rebuildable view.**
  (Composes with step 3's archive/replay, which already rebuilds Postgres from
  the cold tier.)

## Backends (swap by config, same interfaces)

| Seam | Interface | Default (in-tree, tested) | Production swap |
|------|-----------|---------------------------|-----------------|
| Log | `EventLog` (`append`/`poll`/`commit`/`lag`) | `SqlEventLog` — append-only `log_records` + `log_offsets` on Postgres/SQLite | `KafkaEventLog` (Kafka/Redpanda) |
| Analytics | `AnalyticsSink` (`write`) | `NullAnalyticsSink` / `NdjsonAnalyticsSink` (cold archive) | `ClickHouseAnalyticsSink` |
| Collector tier | OTLP/HTTP `POST /otlp/v1/metrics` | — | any OpenTelemetry Collector exporting OTLP |

The Kafka and ClickHouse adapters lazily import their optional client libs and
are validated in staging against real infrastructure; CI exercises the SQL log
+ NDJSON sink end to end. Nothing downstream of the interfaces changes when the
backend is swapped.

## Configuration (all opt-in; defaults preserve current behavior)

| Setting | Default | Effect |
|---------|---------|--------|
| `PRAETOR_INGEST_VIA_LOG` | `false` | Ingest appends to the log; consumers materialize |
| `PRAETOR_LOG_BACKEND` | `sql` | `sql` or `kafka` |
| `PRAETOR_KAFKA_BOOTSTRAP_SERVERS` | — | Kafka/Redpanda brokers |
| `PRAETOR_ANALYTICS_SINK` | `none` | `none` / `ndjson` / `clickhouse` |
| `PRAETOR_CLICKHOUSE_DSN` | — | ClickHouse connection |
| `PRAETOR_CONSUMER_BATCH_SIZE` | `1000` | Records drained per topic/run |

The `praetor.log.consume` Celery beat task drains the log; with
`ingest_via_log=false` nothing is published and it is a no-op.

## Consequences

- **Ingest is now O(1) append**, horizontally scalable; the three workloads
  decouple; ordering is handled by the log, not the DB.
- **Trade-off:** the hot store is eventually consistent with ingest (records
  are queryable after the consumer runs, not on the ingest request). This is
  the CQRS read-model lag and is acceptable for security telemetry.
- **Operational cost:** in production the log/analytics backends are real
  infrastructure (Kafka, ClickHouse). Small deployments stay on the SQL log +
  NDJSON with no extra services — the log-centric design works at both scales.

## Not done here

- Multi-partition parallel consumers for the SQL log (single ordered drain
  today). Kafka gets this for free via partitions + consumer instances.
- OTLP traces/logs receivers (only metrics today; traces would map to audit but
  lack the SDK's hash chain, so native `/audit/events` stays the audit path).
