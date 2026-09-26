# 3. Tools, Prompts, Resources, and Content Security

[← Identity and authorization](02-identity-and-authorization.md) | [README](../README.md) | [Next: Transport →](04-transport-and-network.md)

The model may propose a call; deterministic code must decide whether the call is valid and authorized. Treat all server-supplied definitions and content as hostile until constrained.

## Validate tool inputs

Use closed, typed schemas with explicit lengths, ranges, formats, and enums. Reject unknown properties. Then canonicalize and apply business rules and authorization.

```ts
import { z } from "zod";

const CreateIssue = z.object({
  project: z.string().regex(/^[A-Z][A-Z0-9_]{1,19}$/),
  title: z.string().trim().min(1).max(160),
  priority: z.enum(["low", "medium", "high"]),
  labels: z.array(z.string().regex(/^[a-z0-9-]{1,32}$/)).max(10),
}).strict();

async function createIssue(raw: unknown, ctx: Context) {
  const input = CreateIssue.parse(raw);
  await authorize(ctx, "issues.create", input.project);
  await requireApprovalIfHighRisk(ctx, input);
  return issueApi.create(input);
}
```

JSON Schema validation is a first step, not a complete defense. Also validate:

- cross-field invariants and expected units;
- decoded/canonical values, Unicode, paths, URLs, and identifiers;
- tenant/object ownership from trusted storage;
- total payload size, nesting depth, arrays, regex complexity, and `$ref` expansion;
- operation intent, current workflow state, and safe retry semantics.

Do not automatically dereference remote schema `$ref` values. If required, allowlist destinations and apply SSRF controls.

## Treat all returned content as untrusted

Tool results, resources, prompt templates, errors, icons, annotations, and metadata can contain prompt injection or malicious markup.

- Label provenance so the model and UI know which server supplied each value.
- Keep instructions separate from data; never merge tool output into a system/developer message.
- Parse expected structured output against a schema.
- Render text as text; sanitize HTML/Markdown and disable active content.
- Remove secrets and unnecessary sensitive fields before model ingestion.
- Do not execute commands, follow URLs, or invoke tools merely because output requests it.
- Apply source-to-sink policy: sensitive source data must not flow to an untrusted destination.

```ts
const SearchResult = z.object({
  records: z.array(z.object({
    id: z.string().uuid(),
    title: z.string().max(200),
    excerpt: z.string().max(2_000),
  }).strict()).max(50),
}).strict();

const parsed = SearchResult.parse(toolResult.structuredContent);
const safeForModel = redactSecrets(parsed);
```

## Tool-definition integrity

Tool descriptions and schemas influence model behavior before a tool is called. Defend against poisoning, “rug pulls,” and semantic drift:

1. Authenticate the server and publisher.
2. Namespace each tool by stable server identity; reject duplicate fully qualified names.
3. Canonicalize and hash names, descriptions, schemas, annotations, and requested permissions.
4. Record the approved manifest and package/image digest.
5. Diff on reconnect and before sensitive use.
6. Quarantine and require re-review for material changes.
7. Never silently grant new tools, fields, destinations, or privileges.

```ts
const canonical = canonicalJson({
  serverId,
  tools: tools
    .map(({ name, description, inputSchema, annotations }) => ({
      name, description, inputSchema, annotations,
    }))
    .sort((a, b) => a.name.localeCompare(b.name)),
});
const digest = `sha256:${sha256(canonical)}`;

if (approvedDigest !== digest) {
  await quarantineServer(serverId, "tool_manifest_changed");
}
```

Never resolve a collision using “first/last writer wins.” Bind approval and authorization to `(authenticated server ID, tool name, schema digest)`, not the display name alone.

## Tool design

Prefer narrow tools such as `invoice.get` and `invoice.mark_paid` over `execute_api_request` or `run_command`.

Good tools:

- have one clear business purpose;
- expose enums and typed IDs rather than free-form code;
- derive tenant/user context from authentication, not arguments;
- declare side effects, idempotency, cost, and data classification;
- return minimal structured data;
- support dry-run or preview for sensitive writes;
- use idempotency keys for retryable mutations.

Avoid generic shells, arbitrary URL fetchers, raw SQL, unrestricted file operations, and tools that accept credentials.

## Dangerous sinks

### OS commands

Use native libraries first. If process execution is unavoidable, use a fixed executable and separated, validated arguments with no shell.

```python
from pathlib import Path
import subprocess

ALLOWED_REPORTS = {"daily", "weekly"}

def render_report(name: str, output_dir: Path) -> None:
    if name not in ALLOWED_REPORTS:
        raise ValueError("unsupported report")
    safe_root = output_dir.resolve()
    output = (safe_root / f"{name}.pdf").resolve()
    if safe_root not in output.parents:
        raise ValueError("path escapes output directory")

    subprocess.run(
        ["/usr/local/bin/report-renderer", "--report", name, "--out", str(output)],
        shell=False, check=True, timeout=30,
        env={"PATH": "/usr/bin:/bin"},
    )
```

Never use `exec`, `eval`, `sh -c`, `bash -c`, or string-built command lines with model input.

### SQL

Use parameterized statements and a narrowly privileged database identity:

```python
row = db.execute(
    "SELECT id, status FROM tickets WHERE tenant_id = ? AND id = ?",
    (principal.tenant_id, ticket_id),
).fetchone()
```

Allowlist identifiers that cannot be bound. Do not offer arbitrary query tools in production.

### Paths

Resolve and canonicalize paths, then enforce containment in an approved root. Reject absolute paths, traversal, symlink escapes, device files, and unsafe archive entries. Open files with safe flags and least privilege.

### URLs and SSRF

Parse with a standards-compliant URL parser. Allowlist scheme, destination, and port; resolve DNS; reject loopback, private, link-local, multicast, and cloud metadata addresses; and repeat validation after redirects and DNS changes. See [Transport](04-transport-and-network.md#outbound-request-and-ssrf-defense).

### Templates and rendered content

Use auto-escaping templates. Sanitize rich content. Apply a restrictive Content Security Policy to any webview and disable scripts, forms, external resources, and dangerous URI schemes unless explicitly required.

## Approval and intent validation

For high-risk operations:

1. Generate a server-side preview from validated arguments.
2. Show target, destination, data, effect, and authenticated server.
3. Bind the approval cryptographically or server-side to the normalized arguments and expiry.
4. Revalidate policy immediately before execution.
5. Reject changed arguments; do not “edit” an existing approval.

```ts
const approval = await approvals.require({
  principalId: ctx.principal.id,
  serverId: ctx.server.id,
  tool: "payments.send",
  argsDigest: sha256(canonicalJson(validatedArgs)),
  maxAgeSeconds: 120,
  singleUse: true,
});
```

Use dual control for exceptional operations such as key export, mass deletion, privilege grants, or production deployment.

## Cross-server isolation

Combining a sensitive server and an untrusted content server in one model context creates a data-exfiltration path. Prefer separate agents/contexts and:

- restrict which outputs may become arguments to another server;
- redact sensitive data before handoff;
- enforce destination-aware information-flow policy;
- require approval when data crosses server or trust boundaries;
- cap chained calls and block recursion.

## Roots, sampling, and loops

Roots and Sampling are deprecated in MCP 2026-07-28. For legacy support:

- roots are hints, not access-control boundaries;
- validate and enforce paths server-side;
- require user review of sampling messages and tool use;
- isolate sensitive context, limit tokens/cost/time, and cap loop depth;
- never honor cross-server context requests automatically.

## Error handling

Return stable codes and safe messages:

```json
{
  "code": "TOOL_INPUT_REJECTED",
  "message": "The request did not meet tool requirements.",
  "correlationId": "req_7f3b..."
}
```

Do not return stack traces, raw downstream errors, SQL, filesystem paths, environment variables, credentials, internal hosts, or detailed policy logic.

## Related sources

[MCP Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [MCP Client Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices), [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [OWASP Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), and [Invariant Labs tool-poisoning research](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).
