# 9. Testing and Review Checklists

[← Monitoring and response](08-monitoring-and-incident-response.md) | [README](../README.md) | [Next: References →](10-references.md)

## Security test program

Combine code review, SAST, SCA, secret/container/IaC scanning, protocol tests, authorization tests, fuzzing, adversarial model tests, and production detection validation. Conventional scanners alone do not detect semantic tool poisoning or unsafe delegated authority.

### Unit and integration tests

Test:

- closed schemas, boundaries, Unicode, malformed JSON, depth, size, and unknown fields;
- object/function-level authorization across users, roles, clients, tools, and tenants;
- token signature, issuer, audience/resource, expiry, scope, type, and key rotation;
- OAuth state, PKCE, exact redirects, issuer mix-up, and replay;
- Origin/Host/protocol mismatch and DNS rebinding conditions;
- SSRF through IPv4/IPv6, redirects, DNS changes, alternate notation, and metadata;
- shell/SQL/path/template injection and archive/symlink escapes;
- idempotency, partial failure, timeout, retry, and unknown outcomes;
- rate, concurrency, loop, token, cost, file, and result limits;
- redaction and safe error/log handling;
- state-handle principal/tenant binding.

```ts
it.each([
  "../etc/passwd",
  "%2e%2e/%2e%2e/etc/passwd",
  "/etc/passwd",
  "safe/../../secret",
])("rejects escaping path %s", async (path) => {
  await expect(readFileTool({ path }, context)).rejects.toThrow();
});
```

### Tool-poisoning and prompt-injection tests

Place adversarial instructions in:

- tool names/descriptions/schema titles and field descriptions;
- resources, prompt templates, icons/alt text, errors, and annotations;
- retrieved documents, issue text, web pages, images, and tool results;
- encoded/obfuscated, multilingual, split, and indirect content.

Verify that they cannot:

- bypass policy or approval;
- access hidden context/secrets;
- change destinations or arguments;
- trigger another tool;
- override higher-trust instructions;
- persist across users/tasks.

Use canary secrets and synthetic accounts. Never red-team with real credentials or destructive production access.

### Manifest and collision tests

- Register duplicate names from two servers; the host must reject, not choose.
- Change description/schema/annotations after approval; the host must quarantine.
- Change publisher, endpoint, signing identity, package digest, or permissions.
- Remove and re-add a server under a similar display name.
- Reorder manifest fields; canonical hashing should remain stable.

### Fuzzing

Fuzz MCP framing, JSON-RPC structures, schemas, URLs, file formats, and downstream adapters. Apply memory/time limits to the fuzzer and server. Preserve crashing/minimal cases and convert them to regression tests.

### Adversarial infrastructure tests

- Auth/policy/KMS/audit service unavailable or slow.
- Authorization server key rotation and malicious metadata.
- Downstream timeouts after a mutation.
- Egress proxy bypass attempts.
- Resource exhaustion and decompression bombs.
- Compromised dependency/update and revoked signer.
- Clock skew and expired certificates.

## Release gate checklist

### Design

- [ ] Trust boundaries, data flows, abuse cases, and risk owners are documented.
- [ ] Every tool is classified; broad generic tools are removed or strongly isolated.
- [ ] Model output is not used as authentication or authorization.
- [ ] Sensitive/irreversible actions have preview, approval, and recovery design.
- [ ] Failure modes deny sensitive operations.

### Identity and authorization

- [ ] Remote auth follows MCP OAuth requirements, PKCE, resource indicators, and exact redirects.
- [ ] Tokens are validated for signature, issuer, audience, time, type, and scopes.
- [ ] MCP tokens are never passed upstream.
- [ ] Authorization covers function, object, tenant, arguments, destination, and current policy.
- [ ] Credentials and state handles are isolated and short-lived.

### Tools and data

- [ ] Inputs use closed bounded schemas plus semantic validation.
- [ ] Commands, SQL, paths, URLs, and templates use safe APIs.
- [ ] Tool definitions/results are treated as untrusted and provenance-labelled.
- [ ] Tool names are namespaced; collisions are rejected.
- [ ] Manifest drift causes quarantine/reapproval.
- [ ] Data is minimized, redacted, encrypted, retained, and deleted by policy.

### Transport and runtime

- [ ] TLS, Origin, Host, protocol version, type, size, and timeout controls are enforced.
- [ ] Local HTTP binds to loopback and is authenticated.
- [ ] SSRF controls cover discovery, redirects, DNS, IPv4/IPv6, and metadata.
- [ ] Workloads run non-root with sandbox, resource, and egress restrictions.
- [ ] Retries are bounded; mutations use idempotency or explicit reconciliation.
- [ ] Tenant storage, queues, caches, vectors, and logs are isolated.

### Supply chain and operations

- [ ] Publishers/artifacts are approved, pinned, verified, inventoried, and reproducible.
- [ ] SBOM and provenance are produced and checked.
- [ ] Security scans and MCP-specific adversarial tests pass.
- [ ] Logs exclude secrets and support high-value detections.
- [ ] Kill switch, revocation, rotation, rollback, and incident playbooks are tested.
- [ ] Documentation names the supported MCP version and legacy behavior.

Block release when a required item is false; record a time-bound, owner-approved exception only when compensating controls reduce risk.

## Role-specific checklists

### MCP server developer

- [ ] Verify authenticated principal and tenant from trusted context.
- [ ] Authorize every call and loaded object.
- [ ] Validate/canonicalize all arguments before use.
- [ ] Return minimal typed content and safe errors.
- [ ] Use separate audience-bound downstream credentials.
- [ ] Add idempotency and audit events for mutations.
- [ ] Declare side effects, cost, and data classification accurately.

### MCP client/host developer

- [ ] Authenticate and namespace servers.
- [ ] Treat all server fields/results as hostile.
- [ ] Pin/diff manifests and require meaningful reapproval.
- [ ] Broker secrets outside the model and subprocess environment.
- [ ] Show argument-aware approvals with destination and side effects.
- [ ] Restrict cross-server data flow, loops, and cost.
- [ ] Sandbox local servers and generated code.

### Platform/operator

- [ ] Maintain authoritative inventory, owner, risk, expiry, and destinations.
- [ ] Enforce approved identities/artifacts through a gateway/policy.
- [ ] Default-deny ingress/egress and segment sensitive systems.
- [ ] Monitor first-seen servers, drift, audience failures, exfiltration, and costs.
- [ ] Patch/revoke quickly and test backup/recovery.
- [ ] Discover shadow servers in endpoints, repos, CI, and cloud workloads.

### Security reviewer

- [ ] Trace data from every sensitive source to every external/action sink.
- [ ] Verify authorization independently of prompts and schemas.
- [ ] Review OAuth discovery/redirect/token boundaries.
- [ ] Attempt poisoning, collision, rug-pull, confused-deputy, and passthrough attacks.
- [ ] Review local launch configuration and inherited authority.
- [ ] Verify detection and containment using generated telemetry.

## Suggested CI checks

```yaml
security:
  script:
    - npm ci --ignore-scripts
    - npm run lint
    - npm test
    - npm run test:authorization
    - npm run test:protocol
    - npm run test:adversarial
    - npm audit --audit-level=high
    - detect-secrets scan
    - syft dir:. -o cyclonedx-json=sbom.cdx.json
  artifacts:
    paths: [sbom.cdx.json]
```

Use equivalent tools for your stack, pin CI actions/images, protect artifacts, and treat scanner suppression as a reviewed code change.

## Review cadence

Reassess when:

- the MCP specification or SDK version changes;
- a server, tool manifest, publisher, destination, model, or data class changes;
- a new vulnerability/advisory affects dependencies;
- permissions or architecture expand;
- an incident, near miss, or detection gap occurs;
- at least periodically according to system risk.

## Related sources

[NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final), [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28).
