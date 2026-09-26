# 5. Secrets, Data Protection, and Privacy

[← Transport](04-transport-and-network.md) | [README](../README.md) | [Next: Local servers and supply chain →](06-local-servers-and-supply-chain.md)

## Data inventory and classification

Before enabling a tool, document:

- inputs, outputs, model context, logs, caches, and downstream copies;
- owner, tenant, residency, purpose, and legal basis;
- public/internal/confidential/restricted classification;
- retention/deletion requirements;
- destinations and subprocesses that can receive the data.

Default to the most restrictive classification when metadata is absent.

## Credential isolation

Secrets must never appear in prompts, tool descriptions, tool arguments, resources, URLs, source code, images, errors, or logs.

- Store long-lived secrets in a managed secret service.
- Prefer short-lived workload identity over static keys.
- Issue credentials per environment, server, audience, tenant/user, and purpose.
- Keep the model and MCP subprocess unable to read unrelated credentials.
- Rotate automatically and after personnel, publisher, package, or incident changes.
- Revoke on process exit or server quarantine.
- Never forward an MCP token to an upstream API.

```ts
async function callBilling(ctx: Context, invoiceId: string) {
  const token = await workloadIdentity.getToken({
    audience: "https://billing.internal",
    scopes: ["invoice.read"],
    subject: ctx.principal.id,
    ttlSeconds: 300,
  });

  // token remains in trusted runtime memory, never in model-visible objects.
  return billingClient.getInvoice(invoiceId, token);
}
```

Avoid command-line secrets because process listings and crash reports may expose them. Prefer protected file descriptors, short-lived files with mode `0600`, or platform secret APIs.

## Data minimization

- Provide only fields necessary for the current task.
- Filter and aggregate server-side before data enters model context.
- Use field allowlists rather than denylist-only redaction.
- Truncate long content and cap result counts.
- Separate search from retrieval so the model does not receive entire records.
- Do not include full conversation history in tool calls by default.
- Do not reuse sensitive context across users, tenants, or unrelated tasks.

```ts
function toModelView(customer: Customer) {
  return {
    id: customer.publicId,
    displayName: customer.displayName,
    status: customer.status,
    // Deliberately excludes email, address, notes, tokens, and payment data.
  };
}
```

## Redaction and DLP

Redact before:

- adding data to model context;
- sending it to another MCP server or external destination;
- logging, tracing, analytics, or error reporting;
- showing previews to users without need-to-know.

Use typed field-level handling first and pattern/entropy scanners as defense in depth. Redaction is not reliable if arbitrary text mixes secrets and normal content; prevent that mixing at the source.

```ts
const SAFE_AUDIT_FIELDS = ["event", "requestId", "principalId", "serverId",
  "tool", "decision", "reasonCode", "latencyMs"];

audit.write(pick(event, SAFE_AUDIT_FIELDS));
```

Test redaction for nested objects, arrays, encoded data, headers, query strings, exceptions, and multiline output.

## Storage, retention, and deletion

- Encrypt sensitive data at rest with managed keys and access separation.
- Partition storage and caches by tenant and environment.
- Set explicit TTLs for prompts, results, approvals, cursors, idempotency records, and traces.
- Do not persist content merely because the SDK provides tracing.
- Apply deletion to primary stores, indexes, caches, backups, and derived datasets according to policy.
- Keep audit records only as long as required and minimize their payload.
- Protect backup credentials and regularly test restoration.

State handles must be opaque, high entropy, expiring, and bound server-side to the verified principal. Do not encode sensitive values in a client-visible handle unless encrypted and authenticated—and prefer server-side state.

## Encryption in transit

- Use TLS for all remote MCP, OAuth, registry, and downstream traffic.
- Validate hostnames and certificate chains; never disable verification in production.
- Use mTLS/workload identity where service authentication requires it.
- Protect local IPC with OS permissions and process isolation.
- Rotate certificates and test expiry/renewal failures.

Encryption does not replace authorization or destination validation.

## Privacy and user transparency

Tell users:

- which server/publisher receives data;
- the purpose and fields sent;
- whether a third party/model provider processes it;
- expected retention and region;
- side effects and whether approval can be remembered.

Obtain explicit consent where required. Provide access, correction, export, and deletion workflows as applicable. Avoid dark patterns and consent bundling.

## Sensitive elicitation

MCP form-mode elicitation must not collect passwords, API keys, access tokens, or payment credentials. Use URL-mode interaction with the responsible first/third party, display the full destination, and bind completion to the initiating user. Never put secrets or PII in the elicitation URL.

## Caches and embeddings

- Include tenant, identity, authorization, policy version, and data classification in cache keys.
- Never share cached authorized results across principals unless explicitly public.
- Invalidate when permissions or source records change.
- Treat vector stores and embeddings as sensitive derived data.
- Enforce document-level access before retrieval and again before return.
- Prevent deleted/revoked documents from remaining retrievable.

## Development and testing data

- Do not copy production prompts, tokens, logs, or customer records into development.
- Use synthetic or irreversibly de-identified fixtures.
- Ensure test MCP servers cannot reach production networks or credentials.
- Scrub recordings and bug reports before sharing.

## Related sources

[MCP Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation), [MCP Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations), [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), and [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).
