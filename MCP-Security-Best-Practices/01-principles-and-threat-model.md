# 1. Security Principles and Threat Model

[← README](../README.md) | [Next: Identity and authorization →](02-identity-and-authorization.md)

Security starts with an explicit model of what can go wrong. MCP connects probabilistic models, users, third-party content, credentials, local processes, and high-impact systems; none should inherit trust from another.

## Defense in depth

Use independent controls so a single failure does not expose the system:

1. **Network:** segmentation, private endpoints, egress allowlists, firewalls.
2. **Transport:** TLS, certificate validation, strict Origin/Host policy.
3. **Identity:** user, client, workload, server, and tenant authentication.
4. **Authorization:** per-operation and argument-aware policy.
5. **Validation:** closed schemas, canonicalization, semantic limits.
6. **Execution:** sandboxing, least privilege, time and resource limits.
7. **Data:** minimization, output filtering, encryption, retention controls.
8. **Detection:** auditable decisions, manifest monitoring, anomaly alerts.
9. **Recovery:** token revocation, server quarantine, rollback, key rotation.

Do not count repeated versions of the same control as separate layers. Three prompt instructions are still one model-dependent control.

## Fail securely

Authentication, authorization, policy, schema, discovery, and dependency failures must deny the operation. Return a stable public error and log the internal cause safely.

```ts
async function mayInvoke(ctx: CallContext, tool: string): Promise<boolean> {
  try {
    const decision = await policyEngine.authorize({
      subject: ctx.verifiedSubject,
      clientId: ctx.clientId,
      tenantId: ctx.tenantId,
      tool,
    });
    return decision === "allow";
  } catch (error) {
    securityLogger.error("authorization_unavailable", {
      requestId: ctx.requestId,
      errorType: error instanceof Error ? error.name : "unknown",
    });
    return false; // Fail closed.
  }
}
```

Also fail closed when:

- token metadata cannot be fetched or verified;
- a server identity, protocol version, schema, or tool manifest changes unexpectedly;
- a required approval record is missing, expired, or ambiguous;
- a timeout leaves the outcome of a mutating operation unknown;
- log/audit delivery required by policy is unavailable.

Design an explicit degraded mode for safe read-only operations if availability requirements demand one. Never invent one during an outage.

## Zero trust

Verify every request based on identity, device/workload context, resource, tool, arguments, and current policy. Do not trust an operation merely because it came from:

- an authenticated user;
- the model or system prompt;
- `localhost`, a private network, or a signed package;
- a previously approved server;
- a tool result from another trusted server.

```ts
const ToolCall = z.object({
  name: z.enum(["tickets.search", "tickets.comment"]),
  arguments: z.record(z.unknown()),
}).strict();

async function validateAndAuthorize(raw: unknown, ctx: Context) {
  const call = ToolCall.parse(raw);
  const args = schemas[call.name].parse(call.arguments);
  const normalized = canonicalize(args);

  await policy.requireAllowed({
    principal: ctx.verifiedPrincipal,
    serverId: ctx.authenticatedServerId,
    tool: call.name,
    arguments: normalized,
  });
  return normalized;
}
```

## Trust boundaries

Document the data and authority crossing each boundary:

```text
Untrusted content ─┐
User ──────────────┼─> Host/model ─> deterministic policy ─> MCP server
Tool definitions ─┘        │                                  │
                           └─ approval UI                      ├─ database
                                                              ├─ SaaS API
                                                              └─ OS/network
```

At minimum, identify:

- user ↔ host;
- model ↔ deterministic policy and approval UI;
- host ↔ each MCP server;
- one MCP server ↔ another server's returned content;
- server ↔ authorization server;
- server ↔ downstream APIs, databases, files, shell, and network;
- tenant ↔ tenant;
- build/registry/install pipeline ↔ runtime.

For each boundary, record: identities, credentials, data classes, allowed operations, validation, logging, failure behavior, and owner.

## Security principals and delegated authority

Keep these identities distinct:

- the human or service user;
- the MCP client application;
- the host workload/process;
- the MCP server;
- the downstream service identity;
- the model, which is **not** an authenticated principal.

Authorization should answer: “May this verified user, through this verified client, call this tool on this resource with these arguments now?” A valid connection or token does not answer that question alone.

## Human control and consent

Ask for approval when an action crosses an authorization boundary, exposes sensitive data, has material cost, contacts a new destination, or is destructive/irreversible.

A useful approval shows:

- authenticated server/publisher and tool;
- exact action and target;
- relevant argument values and data leaving the system;
- side effects, cost, and reversibility;
- duration and scope of any remembered grant.

Avoid consent fatigue. Auto-allow low-risk calls only within a narrow, recorded grant. Auto-deny known policy violations. Do not let the server provide trusted approval text.

## Minimum threat scenarios

Threat-model at least these cases:

1. A document or tool result tells the model to leak secrets through another tool.
2. A server hides instructions in its tool description or schema.
3. An approved server changes its manifest after approval (a “rug pull”).
4. An untrusted server registers the same tool name as a trusted server.
5. A token issued for one server is replayed to another or passed upstream.
6. OAuth discovery follows a redirect to cloud metadata or a private service.
7. A hostile website reaches a localhost MCP HTTP server through DNS rebinding.
8. A local stdio configuration launches attacker-controlled commands or inherits secrets.
9. Model-controlled input reaches a shell, SQL query, path, URL, or template.
10. Retries duplicate a payment, deletion, message, or deployment.
11. One tenant references another tenant's object/state handle.
12. A package update or compromised publisher introduces exfiltration.
13. Excessive loops consume tokens, money, CPU, or downstream quotas.
14. Logs capture bearer tokens, prompts, private records, or tool results.
15. Auth, policy, KMS, or audit infrastructure becomes unavailable.

## Risk classification

Classify tools before enabling them:

- **Low:** bounded, read-only, non-sensitive, no external side effects.
- **Moderate:** reads internal data, performs reversible writes, or has limited cost.
- **High:** handles secrets/PII, sends data externally, changes access, runs code, deploys, purchases, deletes, or performs irreversible actions.
- **Prohibited:** cannot be constrained or monitored to acceptable risk.

Raise controls with risk: stronger identity, narrower arguments, shorter grants, mandatory approval, dual control, sandboxing, egress restrictions, and more detailed audit events.

## Anti-patterns

Never:

- trust AI-generated parameters without validation;
- use string concatenation for commands or queries;
- expose stack traces, tokens, internal paths, or policy details to clients;
- store secrets in source, tool descriptions, model context, or logs;
- run MCP servers as root or with a developer's full environment;
- use one broad credential for all users, tools, tenants, and upstreams;
- rely on prompts as the only defense;
- treat roots, state handles, or possession of an object ID as authorization;
- silently resolve tool-name collisions;
- approve an unpinned package command such as `npx -y package@latest`.

## Related sources

[NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final), [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence), [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), and the [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
