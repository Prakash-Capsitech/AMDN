# Reliability

The [F0.5 harness](../Harness/README.md) uses real JetStream file storage and
PostgreSQL transactions to exercise writer/publisher/consumer process kills,
outbox duplicates, deduplicated inbox effects and an offline consumer after
service process restarts. F1.2 also checks committed application identity records
after a PostgreSQL process restart. Run `make harness-test`.

Production worker integration, reconnect cursors, authenticated device receipts,
receipt reordering, expiry/retention races, noisy-neighbor backlog load, multi-node
failover and host power-loss recovery remain pending (P01–P03). Broker ACK never
stands in for DEVICE_ACKED. Native N01/N02 remain separately pending in
[agent safety](../../docs/security/agent-safety.md).
