# Changelog

## Unreleased

- Windows 的 `monitor3-api` 改用 Waitress，避免长期运行时使用 Flask 开发服务器；Linux/容器仍使用 Gunicorn。
- 增加无法访问 Docker Hub/PyPI 场景的 Linux 离线并行部署手册，明确跨平台清理、空库初始化、验收与回滚流程。
- VPN Worker 将华为登录审计与实时会话日志拆分为独立断点，补读当天 `%%01SSLVPN` 审计，并把迟到的公网 IP 与归属地合并到仍在线的活动会话。
- 基础设施心跳按服务采样周期显示“实时、周期内等待、超时”，避免主机、维护和 VPN Worker 被统一短阈值误报离线。
- 控制台聚合首页支持取消重叠刷新，静态 UI 资源启用短期缓存；控制台和态势大屏增加审计完整度、健康汇总及视觉层次优化。

## 3.0.0-dev

- Rebuilt the system around normalized events, SQLite WAL, transactional outbox,
  independent workers, versioned API, and systemd deployment.
- Added safe firewall modes: disabled, dry-run, and live.
- Added plugin contracts and Python entry-point discovery.
- Added reliable file-source checkpoints and packaged database migrations.
- Added vendor-specific Huawei IPS, DPTech IPS/WAF, and Topsec WAF parsers.
- Added a priority policy engine with source, category, severity, count, and geography conditions.
- Wired action, notification, and geolocation implementations through plugin factories.
- Added `monitor3 plugins`, `monitor3 doctor`, and `monitor3 migrate` commands.
- Added hashed API tokens, role-based authorization, trusted audit identities, and token lifecycle CLI commands.
- Added signed generic webhook and SMTP notification providers.
- Added an explicit storage backend protocol and safe rejection of unsupported PostgreSQL configuration.
- Decoupled enforcement and notification into independent outbox tasks so notification failures cannot repeat blocks.
- Added fanout notifications with partial/all-success behavior and delivery audit records.
- Added a verified, idempotent Linux nftables action provider without shell command execution.
- Wired IPv4/IPv6 CIDR whitelists into the decision transaction and added audited management APIs.
- Added an offline static threat-intelligence provider and tag/confidence policy conditions.
- Added notification suppression by stable deduplication key and Prometheus metrics.
- Added content-hash policy hot reload with last-known-good fallback and heartbeat diagnostics.
- Added side-effect-free `simulate` and historical log `replay` commands for SOC rule validation.
- Added consistent SQLite backups, SHA-256 manifests, integrity verification, guarded restore, and automatic pre-restore safety snapshots.
- Added authenticated policy status and simulation APIs.
- Added packaged runtime defaults and verified wheel resources for operation outside the source tree.
- Fixed SQLite context management so Windows file handles are reliably released.
- Added configurable batched retention, daily statistics aggregation, passive WAL checkpointing, and a one-shot maintenance command.
- Added readiness checks for configurable required workers plus database-size and unhealthy-service metrics.
- Unified healthy heartbeat semantics and refreshed action-worker heartbeats while processing busy queues.
- Added oldest-action and per-service heartbeat-age metrics, daily-statistics API, and audited dead-action retries.
- Added API request-size limits, security headers, trusted-proxy controls, authenticated-request rate limiting, and configuration validation.
- Throttled API-token usage timestamps to remove a high-frequency SQLite write-lock hotspot.
- Added opt-in Prometheus and Grafana deployment assets, six operational alert rules, and a provisioned SOC overview dashboard.
- Added weekly dependency auditing, Bandit static analysis, CycloneDX SBOM generation, and verified tag-triggered release artifacts.
- Replaced the broken minimal dashboard with a responsive Chinese SOC console for events, reviews, blacklist, workers, dead actions, and trends.
- Packaged CSP-compatible dashboard assets so source and wheel installations expose the same interface.
- Closed anonymous read access to all `/api/v1` operational data and added automatic dashboard authentication prompts.
- Added cooperative SIGINT/SIGTERM shutdown for all long-running workers so in-flight units finish before service exit.
- Expanded `doctor` validation across plugins, numeric bounds, retention, heartbeats, fanout channels, and plaintext-secret rejection.
- Added parity checks for source/package defaults and required runtime environment variables.
- Added environment-only generic Webhook URL injection and preflight validation for enabled notification providers.
- Added verified daily systemd backups, configurable automatic-backup retention, and safe pruning that preserves manual and pre-restore snapshots.
- Added isolated restore rehearsals that validate current migrations and required application tables without touching the live database.
- Added validated list pagination with `has_more`, consistent JSON 404/405 errors, and request IDs in every response header.
- Added repository-wide UTF-8 and mojibake regression checks for user-facing text assets.
- Added non-leaking JSON handling for unexpected API and readiness failures while retaining correlated server-side diagnostics.
- Serialized SQLite migrations with a cross-process write lock and removed `executescript` implicit commits to support concurrent service startup.
- Added concurrent duplicate-event regression coverage proving one event, decision, blacklist entry, and outbox action under write contention.
- Fixed concurrent first-connection WAL negotiation by applying busy timeout first and retrying only the initial journal-mode transition.
- Added geolocation failure caching and a configurable circuit breaker so provider outages degrade to `UNKNOWN` without dropping events.
- Made collector enrichment fail-open to safe `UNKNOWN`/empty intelligence while preserving parsed events and recording non-sensitive error types.
- Fixed Huawei firewall verification so echoed commands cannot masquerade as successful blocks, and added mandatory post-unblock state checks.
- Added `monitor3 release-check` for machine-readable production acceptance of database, disk, assets, workers, and recent verified backups.
- Added recursive layered configuration over packaged safe defaults plus secret-free production and Compose override templates.
- Expanded Compose to API, action, maintenance, collector, VPN, host, backup, and monitoring profiles with liveness gating and read-only log mounts.
- Stabilized release archive timestamps with `SOURCE_DATE_EPOCH` derived from the tagged source commit.
