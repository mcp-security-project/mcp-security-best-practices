# 4. Transport, Network, and Protocol Security

[← Tools and content](03-tools-and-content-security.md) | [README](../README.md) | [Next: Secrets and privacy →](05-secrets-data-and-privacy.md)

## Version baseline

MCP 2026-07-28 is stateless. Each request carries protocol version and client capabilities in `_meta`; HTTP also carries `MCP-Protocol-Version`. Reject unsupported versions and header/body mismatches.

Do not add `Mcp-Session-Id`, GET streams, or `initialize` to new implementations. Place legacy compatibility behind a separate adapter with explicit tests and sunset date.

## Streamable HTTP

Required controls:

- TLS 1.2+ (prefer 1.3) with normal hostname and certificate validation;
- authentication on remote connections and local HTTP where feasible;
- exact allowlists for `Origin` and `Host`;
- HTTP 403 for invalid `Origin`;
- loopback binding for local servers, never `0.0.0.0`;
- request/content-type/size/time limits;
- matching protocol metadata;
- no bearer tokens in URLs;
- request-scoped SSE only; no assumption that a stream can resume.

```ts
const allowedOrigins = new Set(["https://agent.example.com"]);
const allowedHosts = new Set(["mcp.example.com"]);

app.use((req, res, next) => {
  const origin = req.header("origin");
  const host = req.hostname.toLowerCase();

  if ((origin && !allowedOrigins.has(origin)) || !allowedHosts.has(host)) {
    return res.sendStatus(403);
  }
  if (req.header("mcp-protocol-version") !== "2026-07-28") {
    return res.status(400).json({ code: "UNSUPPORTED_PROTOCOL_VERSION" });
  }
  next();
});

app.listen(8443, "127.0.0.1");
```

Do not confuse CORS with authorization. Browser CORS headers do not protect non-browser clients; authenticate and authorize independently.

### Reverse proxies

- Terminate TLS only at controlled proxies and use authenticated/encrypted service-to-service traffic.
- Strip untrusted forwarding headers; accept them only from known proxies.
- Configure request/response size limits and timeouts.
- Disable request smuggling ambiguities and normalize duplicate headers.
- Preserve a correlation ID without trusting client-supplied identity headers.
- Do not cache authenticated MCP responses unless explicitly safe and partitioned.

## DNS rebinding and localhost

A malicious web page can use DNS rebinding to target a local HTTP server.

- bind to `127.0.0.1` and/or `::1`, not all interfaces;
- validate exact `Origin` and `Host`, including port;
- require a per-installation authentication secret or stronger identity;
- reject absent `Origin` if the endpoint is intended only for a browser-based host;
- avoid wildcard CORS and wildcard host policies;
- use OS firewall/process isolation as another layer.

## stdio

stdio is a process boundary, not a trust boundary.

- launch only approved absolute executable paths;
- use argument arrays with `shell: false`;
- show the full untruncated command before installation;
- strip inherited environment variables and issue server-specific credentials;
- set a controlled working directory, user/group, filesystem, network, CPU, memory, and process limits;
- reserve stdout for MCP frames; send logs to stderr;
- cap message size and nesting;
- terminate on protocol abuse or timeout and clean up descendants.

```ts
const child = spawn("/opt/mcp/bin/read-only-files", ["--root", approvedRoot], {
  shell: false,
  cwd: "/var/empty",
  env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
  stdio: ["pipe", "pipe", "pipe"],
  detached: false,
});
```

Never accept an arbitrary `command`, `args`, environment, or working directory from remote/untrusted input.

## Outbound request and SSRF defense

Apply this to OAuth/OIDC metadata, JWKS, redirects, webhooks, URL tools, schema references, icons, and downstream APIs.

```python
import ipaddress
import socket
from urllib.parse import urlsplit

def validate_destination(raw_url: str, allowed_hosts: set[str]) -> tuple[str, list[str]]:
    url = urlsplit(raw_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("invalid destination")
    host = url.hostname.rstrip(".").lower()
    if host not in allowed_hosts or url.port not in (None, 443):
        raise ValueError("destination not allowlisted")

    addresses = {item[4][0] for item in socket.getaddrinfo(host, 443)}
    for value in addresses:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise ValueError("non-public address rejected")
    return host, sorted(addresses)
```

Production controls should also:

- use a controlled resolver and egress proxy;
- validate all A/AAAA answers and defend against alternate IP notation;
- connect only to the validated IP while preserving TLS hostname verification;
- revalidate each redirect and enforce a small redirect count;
- prevent DNS time-of-check/time-of-use rebinding;
- block private, loopback, link-local, multicast, reserved, and metadata ranges for IPv4/IPv6;
- limit methods, response size, content type, decompression ratio, and time;
- disallow `file:`, `data:`, `javascript:`, `gopher:`, and unknown schemes.

For private enterprise destinations, use an explicit allowlist and separate network path; do not weaken global-address validation generically.

## Safe URL opening

Parse and allowlist before showing/opening an authorization or elicitation URL. Never pass a URL through a shell:

```ts
const url = new URL(rawUrl);
if (url.protocol !== "https:" || !trustedAuthorizationHosts.has(url.hostname)) {
  throw new Error("untrusted authorization URL");
}
await openWithPlatformApi(url.toString()); // No shell interpolation.
```

## Retries and idempotency

In MCP 2026-07-28, interrupted request-scoped SSE is not resumable. A retry is a new request with a new request ID. Therefore:

- automatically retry only safe/idempotent operations;
- use server-enforced idempotency keys for mutations;
- persist a result keyed by principal, tool, normalized argument digest, and idempotency key;
- show “outcome unknown” rather than blindly retrying after an ambiguous failure;
- bound attempts with exponential backoff and jitter.

```ts
const key = request.headers.get("idempotency-key");
const prior = await idempotencyStore.get(principal.id, tool, key);
if (prior) return prior;

const result = await executeOnce();
await idempotencyStore.put(principal.id, tool, key, result, { ttl: "24h" });
return result;
```

## Timeouts and denial-of-service controls

Set independent limits for connect, headers, body, tool execution, downstream calls, and total workflow. Bound:

- requests per principal/client/IP/tool;
- concurrent requests and subprocesses;
- JSON size/depth and schema complexity;
- SSE duration and buffered output;
- tool chain depth, model turns, tokens, and cost;
- decompression, archives, files, and result counts.

Use backpressure and circuit breakers. Avoid synchronized retries during outages.

## Network architecture

- Place internet-facing ingress, MCP servers, authorization services, and sensitive downstreams in separate zones.
- Default-deny server egress and allow only documented destinations.
- Use workload identity/mTLS internally where appropriate.
- Keep management endpoints off the MCP data plane.
- Restrict cloud metadata and control-plane access.
- Monitor DNS, egress, and new destinations per server.

## Related sources

[MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [MCP stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio), [MCP Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning), [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), and [SEP-1024](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-).
