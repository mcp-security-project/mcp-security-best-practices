# 2. Identity, Authentication, and Authorization

[← Principles](01-principles-and-threat-model.md) | [README](../README.md) | [Next: Tools and content →](03-tools-and-content-security.md)

## OAuth for remote HTTP servers

For Streamable HTTP, implement the MCP authorization specification and OAuth 2.1 profile. The MCP server is a protected resource; it must not accept arbitrary identity-provider tokens.

Required baseline:

- publish RFC 9728 Protected Resource Metadata;
- discover authorization-server metadata through approved issuers;
- use authorization-code flow with PKCE `S256`;
- include the canonical MCP server URI as RFC 8707 `resource` in authorization **and** token requests;
- exact-match redirect URIs and validate single-use, expiring `state`;
- use TLS except for defined loopback development redirects;
- keep access tokens out of query strings, URLs, logs, and model context;
- prefer short-lived access tokens and rotate refresh tokens for public clients;
- bind stored client registration/credentials to the authorization-server issuer.

OAuth 2.1 remains an Internet-Draft as of this guide's cutoff. Apply finalized [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) security best current practice too.

```ts
const verifier = base64url(crypto.randomBytes(64));
const challenge = base64url(
  crypto.createHash("sha256").update(verifier).digest(),
);
const state = base64url(crypto.randomBytes(32));

savePendingFlow({
  stateHash: sha256(state),
  pkceVerifier: verifier,
  expectedIssuer,
  redirectUri,
  resource: canonicalMcpServerUrl,
  expiresAt: Date.now() + 5 * 60_000,
});

authorizationUrl.searchParams.set("code_challenge", challenge);
authorizationUrl.searchParams.set("code_challenge_method", "S256");
authorizationUrl.searchParams.set("state", state);
authorizationUrl.searchParams.set("resource", canonicalMcpServerUrl);
```

At callback, consume `state` once, compare the response `iss` to the expected issuer, use the saved verifier, and repeat `resource` in the token request.

## Validate every access token

Before processing each request:

1. Accept the token only from `Authorization: Bearer`.
2. Verify the cryptographic signature with an approved algorithm and key.
3. Validate exact issuer, expected audience/resource, time claims, and token type.
4. Validate scopes/authorization details for the requested operation.
5. Apply revocation or introspection policy where required.
6. Map the subject and tenant to an internal principal; never trust user-supplied identity fields.

```ts
const claims = await jwtVerify(token, trustedJwks, {
  issuer: config.authorizationIssuer,
  audience: config.canonicalMcpResource,
  algorithms: ["ES256", "RS256"],
  clockTolerance: 30,
});

if (claims.payload.typ && claims.payload.typ !== "at+jwt") {
  throw new Unauthorized("unexpected token type");
}
requireScopes(claims.payload.scope, requiredScopesFor(toolName));
```

Do not decode a JWT and call that validation. Reject `alg: none`, algorithm confusion, unknown issuers/keys, expired/not-yet-valid tokens, and tokens whose audience does not identify this server.

## No token passthrough

MCP forbids forwarding its access token to an upstream API. Passthrough breaks audience restriction, leaks authority, and obscures attribution.

```ts
// Wrong: upstream sees a token intended for the MCP server.
await fetch(upstreamUrl, {
  headers: { Authorization: request.headers.authorization! },
});

// Correct: use a separately obtained, audience-bound upstream token.
const upstreamToken = await tokenBroker.forUpstream({
  subject: principal.id,
  audience: "https://api.example.com",
  scopes: ["tickets.read"],
});
await fetch(upstreamUrl, {
  headers: { Authorization: `Bearer ${upstreamToken}` },
});
```

Keep credentials isolated by server, audience, tenant, user, and purpose. Do not expose downstream tokens to the model or return them in tool output.

## Authorization model

Use deny-by-default policies evaluated at invocation time. A tool's presence in the model context is not permission to use it.

Evaluate:

- verified user/service and tenant;
- authenticated client and server identities;
- exact server namespace, tool, resource, and operation;
- normalized arguments and target object ownership;
- data classification, destination, time, device/workload posture;
- current grant, approval, risk, rate, and spend limits.

```rego
package mcp.tools

default allow := false

allow if {
  input.principal.tenant_id == input.resource.tenant_id
  input.server_id == "support-mcp.prod.example"
  input.tool == "tickets.read"
  "tickets:read" in input.token.scopes
  input.resource.classification in {"public", "internal"}
}
```

Enforce object-level authorization after loading the object from trusted storage. Never authorize from an argument such as `tenantId` alone.

## Least privilege and step-up

- Start with minimal baseline scopes.
- Define scopes around business capabilities, not implementation endpoints.
- Separate read, write, delete, admin, export, and secret access.
- Request operation-specific step-up only when needed.
- Bound approval by tool, arguments/resource, destination, duration, and use count.
- Cap step-up retries to prevent consent loops.
- Revoke grants when the server, tool manifest, user role, or risk changes.

Avoid a single `mcp:*` scope. Scope is necessary but not sufficient; still perform object- and function-level checks.

## Confused-deputy prevention

An MCP server that proxies authorization to an upstream service can become a confused deputy.

- Obtain explicit consent for each MCP client identity.
- Show the client identity and exact redirect URI.
- Register and exact-match redirects.
- Bind consent, `state`, PKCE verifier, issuer, redirect, and resource to one flow.
- Never infer MCP-client consent from an upstream provider's login cookie.
- Do not accept authorization codes initiated by a different client.

## stdio identity

The MCP specification says stdio credentials should come from the environment, but inheriting the user's entire environment is unsafe. The host should act as a credential broker:

```ts
spawn("/opt/approved/mcp-files", ["--mode=readonly"], {
  shell: false,
  uid: dedicatedUid,
  gid: dedicatedGid,
  env: {
    PATH: "/usr/bin:/bin",
    MCP_CREDENTIAL_FILE: oneTimeCredentialFile,
  },
  stdio: ["pipe", "pipe", "pipe"],
});
```

Issue short-lived, server-specific credentials; strip unrelated environment variables; protect the credential file; and revoke it when the subprocess exits.

## State handles are not credentials

Opaque cursors, workflow IDs, elicitation IDs, and legacy session IDs identify state; they do not authorize access. Use high entropy, short expiry, and server-side binding to principal, tenant, client, purpose, and relevant request context. Reauthorize every use.

## Elicitation and account binding

- Never collect passwords, API keys, access tokens, or payment credentials in form-mode elicitation.
- Use URL mode for sensitive or third-party authorization.
- Show the verified requesting server and full destination URL.
- Do not prefetch or expose the destination page to the model.
- Put no PII or bearer-style secret in the URL.
- Prove the user completing the browser flow is the user who initiated it.
- Keep third-party credentials separate from MCP authorization.

## Authentication failure responses

Return minimal, standards-compliant errors. Do not reveal whether a user, tenant, object, token key, or policy exists. Log a correlation ID and safe reason code internally.

## Related sources

[MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [MCP Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html), and [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html).
