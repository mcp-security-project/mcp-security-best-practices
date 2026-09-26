# 6. Local Servers and Software Supply Chain

[← Secrets and privacy](05-secrets-data-and-privacy.md) | [README](../README.md) | [Next: Deployment →](07-deployment-and-runtime.md)

A local MCP server is executable code with the host user's reach. Package ownership or registry presence does not prove safety.

## Safe local server installation

Before installation or first launch:

1. Resolve an approved server ID to a fixed publisher, package/image, version, digest, executable, arguments, and permissions.
2. Verify publisher identity through independent official channels.
3. Show the **complete, untruncated** command, arguments, working directory, requested environment, network, and filesystem access.
4. Warn for shells, interpreters, package runners, remote scripts, privileged flags, mounts, and secret access.
5. Require affirmative consent and allow cancellation.
6. Install into an isolated location as a low-privilege identity.

Avoid:

```json
{
  "command": "npx",
  "args": ["-y", "some-server@latest"]
}
```

Prefer a verified, pinned artifact:

```json
{
  "serverId": "com.example.readonly-files",
  "executable": "/opt/mcp/com.example.readonly-files/1.4.2/server",
  "artifactDigest": "sha256:REPLACE_WITH_VERIFIED_DIGEST",
  "args": ["--config", "/etc/mcp/readonly-files.json"],
  "network": "none",
  "runAs": "mcp-files"
}
```

Configuration files are code-adjacent. Restrict who can modify user/workspace MCP configuration and do not let repository content silently install or alter a server.

## Process sandbox

Restrict:

- user/group and Linux capabilities/OS entitlements;
- filesystem to read-only approved roots plus a private temporary directory;
- network to explicit destinations—or none;
- environment to a small allowlist;
- child processes, syscalls, devices, IPC, and metadata services;
- CPU, memory, file size, open files, process count, and wall time.

Containers are useful but are not a complete sandbox. Use non-root users, read-only filesystems, dropped capabilities, seccomp/AppArmor/SELinux, no host socket, no privileged mode, and controlled mounts.

```yaml
services:
  mcp-server:
    image: registry.example/mcp/files@sha256:REPLACE_WITH_DIGEST
    user: "10001:10001"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    network_mode: "none"
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
    pids_limit: 64
    mem_limit: 256m
```

## Dependency and artifact controls

- Pin direct and transitive dependencies with lockfiles and hashes.
- Pin container images by digest, not mutable tag.
- Verify package/image signatures and approved trust roots.
- Require provenance from approved builders (for example, SLSA provenance).
- Generate SPDX or CycloneDX SBOMs for servers, clients, images, and plugins.
- Scan source, dependencies, containers, IaC, licenses, and secrets.
- Disable unnecessary install scripts and network access during builds.
- Use isolated, ephemeral builds and protect signing keys.
- Rebuild/release instead of patching production artifacts in place.

Signatures prove origin and integrity, not benign behavior. Pair them with review, sandboxing, policy, and runtime monitoring.

Example CI policy:

```yaml
supply-chain:
  script:
    - npm ci --ignore-scripts
    - npm audit --audit-level=high
    - syft dir:. -o cyclonedx-json=sbom.cdx.json
    - cosign verify --certificate-identity-regexp '^https://ci.example/'
        registry.example/mcp/server@"$IMAGE_DIGEST"
    - slsa-verifier verify-image registry.example/mcp/server@"$IMAGE_DIGEST"
        --source-uri github.com/example/mcp-server
```

Adapt commands to your ecosystem and pin the CI tools themselves.

## Update and change control

Stage updates with synthetic data and restricted egress. Compare:

- package/image digest and provenance;
- publisher/signing identity;
- dependencies, install scripts, permissions, destinations;
- tool names, descriptions, schemas, annotations, and behavior;
- output fields and data volume.

Quarantine on unexpected change. Require reapproval for new privileges, destinations, tools, sensitive fields, or side effects. Maintain rollback and emergency revocation.

Do not auto-run the newest package release in production. The malicious `postmark-mcp` incident demonstrated that a package may build trust over multiple releases and later add exfiltration behavior.

## Tool-manifest governance

Store an approved manifest:

```json
{
  "serverId": "com.example.support",
  "publisher": "Example Inc.",
  "artifact": "sha256:...",
  "toolManifest": "sha256:...",
  "allowedTools": ["tickets.search", "tickets.comment"],
  "egress": ["support-api.example.com:443"],
  "dataClasses": ["internal"],
  "approvedUntil": "2026-12-31T00:00:00Z"
}
```

Bind each runtime server identity to this record. Reject tool collisions and definitions not present in the approved manifest.

## Inventory and governance

Continuously inventory:

- remote endpoints and authenticated identities;
- local processes and executable paths;
- IDE/user/workspace configuration;
- CI workflows and build agents;
- package dependencies and container images;
- tool manifests, permissions, credentials, owners, and data classes;
- last use, approval expiry, and known vulnerabilities.

Route remote servers through a governed gateway where practical. Alert on unknown endpoints, unmanaged local processes, new destinations, or configuration drift. Remove unused servers and stale credentials.

## Registry and publisher trust

Official registry validation can reduce namespace impersonation, but it does not certify security or future behavior.

- Verify package namespace ownership and official vendor linkage.
- Prefer organization-controlled namespaces.
- Review source and release history.
- Require multiple maintainers and protected releases for critical servers.
- Monitor ownership transfer, dormant maintainer revival, and signing-key changes.
- Maintain an internal allowlist and risk owner.

## Vulnerability response

For every server, know how to:

- disable it centrally;
- revoke MCP and upstream credentials;
- block package versions, images, digests, publishers, and destinations;
- locate every installation and invocation;
- roll back safely;
- preserve logs/artifacts for investigation;
- notify affected users and owners.

## Related sources

[SEP-1024 Local Server Installation](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-), [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final), [SLSA v1.2](https://slsa.dev/spec/v1.2/), [SPDX](https://spdx.dev/use/specifications/), [CycloneDX](https://cyclonedx.org/), [CISA SBOM resources](https://www.cisa.gov/sbom), [Official MCP Registry requirements](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/official-registry-requirements.md), and [Postmark's malicious-package statement](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package).
