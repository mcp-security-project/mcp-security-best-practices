# 7. Deployment and Runtime Hardening

[← Local servers and supply chain](06-local-servers-and-supply-chain.md) | [README](../README.md) | [Next: Monitoring and response →](08-monitoring-and-incident-response.md)

## Reference architecture

```text
User/Host
   │ TLS + OAuth (audience-bound)
   ▼
MCP ingress ──> authentication ──> policy/approval ──> tool dispatcher
                    │                    │                    │
                    └──── audit events ──┴────────────────────┤
                                                             ▼
                                              isolated tool workload
                                                │           │
                                         egress proxy   scoped data/API
```

Keep model planning separate from authentication, authorization, approval, secrets, and execution. All high-impact paths must pass deterministic controls.

## Sandboxing and least privilege

- One dedicated, non-root workload identity per server/risk domain.
- Read-only base image/filesystem; writable ephemeral paths only.
- Drop capabilities and block privilege escalation.
- Restrict syscalls, process creation, devices, sockets, and host mounts.
- Never mount container runtime sockets or broad home directories.
- Grant database/cloud/API permissions per tool group, not per cluster.
- Keep admin interfaces on a separate authenticated management plane.

Example Kubernetes fragment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: support-mcp
spec:
  template:
    spec:
      automountServiceAccountToken: false
      containers:
        - name: server
          image: registry.example/support-mcp@sha256:REPLACE_WITH_DIGEST
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits: { cpu: "1", memory: 512Mi }
```

Add a default-deny NetworkPolicy and explicit egress; a security context alone does not constrain network access.

## Resource and cost controls

Set limits at user, client, tenant, server, tool, and downstream levels:

- requests/time and concurrent operations;
- CPU, memory, processes, files, body/result size, and execution time;
- model tokens, turns, tool-chain depth, recursion, and total workflow duration;
- external API quota and monetary spend;
- approval prompts and authorization step-up attempts.

```ts
await limiter.require({
  keys: [ctx.tenantId, ctx.principal.id, serverId, toolName],
  requests: 20,
  windowSeconds: 60,
  concurrent: 3,
  estimatedCostCents: estimateCost(args),
});
```

Use queue bounds, backpressure, circuit breakers, and per-tenant bulkheads. A downstream outage should not exhaust all workers.

## Egress control

Default-deny network egress. Allow only protocol, host, port, and—where possible—API operation needed by the tool.

- Route HTTP through an authenticated egress proxy.
- Block cloud metadata, control planes, internal DNS, and private ranges unless explicitly required.
- Alert on first-seen and denied destinations.
- Prevent direct DNS/DoH bypass and raw sockets.
- Separate servers that handle sensitive sources from servers that can send arbitrary external data.

## Tenant isolation

- Derive tenant from verified identity, never a model argument.
- Include tenant in every authorization and storage query.
- Use row-level security or separate stores/keys for stronger boundaries.
- Partition queues, caches, rate limits, files, vectors, state handles, and logs.
- Test object-reference and cache-key attacks.
- Prevent one tenant's tool definitions, approvals, results, or history entering another tenant's context.

```sql
SELECT id, status
FROM tickets
WHERE tenant_id = :verified_tenant
  AND id = :validated_ticket_id;
```

For high-assurance workloads, use separate processes/accounts/projects rather than relying only on application predicates.

## Configuration

- Validate configuration against a schema at startup.
- Keep secure defaults; require explicit opt-in for dangerous features.
- Separate environments/accounts and credentials.
- Encrypt sensitive configuration and restrict changes.
- Record who changed policy, manifests, destinations, and server approvals.
- Reject unresolved placeholders and debug flags in production.
- Pin protocol versions and declare a compatibility/deprecation policy.

## Availability and resilience

- Define behavior when identity, policy, secret, audit, or downstream services fail.
- Fail closed for sensitive operations.
- Permit only predesigned read-only degraded modes.
- Use idempotency for mutations and reconciliation for unknown outcomes.
- Back up policy, approval, inventory, and audit configuration.
- Test restore, regional failure, dependency compromise, and mass revocation.

Health endpoints must not expose tool lists, versions, environment, dependency details, or credentials.

## Production hardening checklist

- [ ] Remote MCP endpoints use TLS and authenticated clients.
- [ ] Ingress enforces Host, Origin, protocol version, types, sizes, and timeouts.
- [ ] Authorization is per operation and object.
- [ ] Workloads are non-root, immutable, and resource-limited.
- [ ] Egress is default-deny and monitored.
- [ ] Secrets are short-lived, audience-bound, and brokered outside model context.
- [ ] Artifacts are pinned, signed/verified, inventoried, and reproducible.
- [ ] Multi-tenant stores/caches/queues are partitioned.
- [ ] Tool loops, retries, and costs are bounded.
- [ ] Logs are centralized, redacted, access-controlled, and tamper-evident.
- [ ] Emergency server disablement and credential revocation are tested.

## Related sources

[MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices), [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final), [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [OWASP API Security Top 10](https://owasp.org/www-project-api-security/), and [MCP Client Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices).
