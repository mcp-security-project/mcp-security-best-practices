# 8. Monitoring and Incident Response

[← Deployment](07-deployment-and-runtime.md) | [README](../README.md) | [Next: Testing and checklists →](09-testing-and-review-checklists.md)

Monitoring should reveal who attempted what, through which server/tool, against which resource, under which policy—without recording secrets or unnecessary content.

## What to record

Use structured, UTC-timestamped security events:

- event ID, correlation/trace ID, timestamp, environment;
- verified principal, tenant, client, workload, and server IDs;
- fully qualified tool/resource and manifest digest;
- authorization decision, reason code, policy version, scopes (not token);
- approval ID/type/scope and whether it was consumed;
- normalized target identifiers and data classification;
- outcome, latency, retry/idempotency status, bytes, and estimated cost;
- downstream service/destination (not credential or sensitive URL query);
- schema, rate-limit, egress, signature, and sandbox violations;
- registration, definition, permission, publisher, and configuration changes.

```json
{
  "event": "mcp.tool.authorization",
  "timestamp": "2026-09-27T00:00:00Z",
  "requestId": "req_...",
  "principalId": "usr_...",
  "tenantId": "ten_...",
  "serverId": "support-mcp.prod",
  "tool": "tickets.comment",
  "manifestDigest": "sha256:...",
  "decision": "deny",
  "reasonCode": "APPROVAL_REQUIRED",
  "policyVersion": "2026-09-20.3"
}
```

Do **not** record:

- bearer/refresh tokens, authorization codes, PKCE verifiers, cookies, or API keys;
- passwords, payment credentials, or private keys;
- complete prompts, conversation history, tool arguments, or results by default;
- sensitive headers, URL query strings, raw exceptions, or environment dumps.

Sanitize CR/LF and delimiters to prevent log injection. Restrict log access, encrypt transport/storage, and use integrity/tamper controls.

## High-value detections

Alert or investigate:

- unknown/unapproved server, process, package, endpoint, or publisher;
- tool manifest/schema/description/permission drift;
- tool name collisions or server identity changes;
- token issuer/audience/signature/scope failures;
- repeated authorization, schema, Origin, Host, or state failures;
- scope inflation and repeated step-up/approval prompts;
- new/denied egress, private-network targets, metadata IPs, or DNS anomalies;
- sudden data-volume growth, bulk reads, exports, or cross-tenant references;
- command/process launches, new child binaries, or sandbox violations;
- unusual tool chains, recursion, high turn count, retries, cost, or latency;
- secrets detected in model context, logs, arguments, or output;
- signature/provenance/SBOM verification failures;
- disabled controls, debug mode, policy changes, or log gaps.

Correlate model-facing events with identity, endpoint, network, cloud, database, and downstream SaaS telemetry.

## Metrics and service objectives

Track:

- allowed/denied/error calls by server and tool;
- high-risk approval rate and abandoned prompts;
- schema failure and injection-detection rates;
- first-seen servers/tools/destinations;
- manifest changes and time to reapproval;
- token validation failures;
- p95/p99 latency, timeouts, retries, unknown outcomes;
- rate-limit, budget, and sandbox violations;
- time to inventory, quarantine, revoke, and recover.

Metrics must not contain high-cardinality sensitive arguments.

## Incident playbooks

### Malicious or compromised server

1. Disable/quarantine the server and block its identity, endpoint, artifact digest, and destinations.
2. Stop active workflows; preserve process, manifest, package/image, network, and audit evidence.
3. Revoke MCP and downstream credentials accessible to it.
4. Identify users, tenants, calls, data, and downstream systems affected.
5. Search for definition changes, collisions, prompt injection, and exfiltration.
6. Rotate secrets and repair altered data/configuration.
7. Rebuild from verified source, reapprove explicitly, and monitor closely.

### Token exposure or passthrough

1. Revoke affected access/refresh tokens and upstream credentials.
2. Block tokens by issuer/audience/key where necessary.
3. Determine logs, prompts, tools, servers, and third parties that received them.
4. Remove stored copies and fix the data flow.
5. Rotate related credentials and review anomalous use.

### Tool poisoning or rug pull

1. Freeze current and previously approved manifests.
2. Disable changed tools and cross-server workflows.
3. Diff descriptions, schemas, annotations, permissions, outputs, and package artifacts.
4. Find calls made after the change and inspect source-to-sink data flows.
5. Restore a verified version; require fresh approval.

### Supply-chain compromise

1. Block publisher/version/digest/signing key and halt rollout.
2. Locate every build, cache, installation, and execution.
3. Preserve artifact, SBOM, provenance, build logs, and network telemetry.
4. Rotate credentials reachable from affected workloads.
5. Rebuild from a known-good commit in a clean trusted builder.

### Cross-tenant exposure

1. Disable the affected tool/path and preserve evidence.
2. Identify source and recipient tenants and exposed records.
3. Fix authorization, query, cache, queue, or state binding.
4. Invalidate caches/handles and rotate credentials if needed.
5. Follow legal, contractual, and customer notification requirements.

## Readiness

- Assign server/tool owners and a 24/7 escalation path for critical systems.
- Maintain offline access to inventory and revocation procedures.
- Pre-authorize containment actions.
- Test central kill switches and credential rotation.
- Run table-top exercises for poisoning, token theft, package compromise, and data exfiltration.
- Preserve clocks, correlation, and evidence chain of custody.
- Feed lessons into threat models, tests, policies, and user interfaces.

## Related sources

[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [NIST SP 800-53 AU/IR controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), and [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).
