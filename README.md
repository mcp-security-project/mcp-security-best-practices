# Model Context Protocol (MCP) Security Best Practices

A practical, defense-in-depth guide for designing, building, reviewing, and operating secure MCP clients, servers, gateways, and tool ecosystems.

> **Baseline:** This guide targets the released MCP specification **2026-07-28**. That version is stateless and removed protocol-level sessions, `Mcp-Session-Id`, HTTP GET streams, and `initialize`. If you support an older MCP version, isolate its compatibility code and apply the legacy session guidance linked in the [references](MCP-Security-Best-Practices/10-references.md).

## Start here

- **Building a server:** [Principles](MCP-Security-Best-Practices/01-principles-and-threat-model.md) → [Identity and authorization](MCP-Security-Best-Practices/02-identity-and-authorization.md) → [Secure tools](MCP-Security-Best-Practices/03-tools-and-content-security.md) → [Transport](MCP-Security-Best-Practices/04-transport-and-network.md)
- **Building a client or host:** [Secure tools](MCP-Security-Best-Practices/03-tools-and-content-security.md) → [Local servers and supply chain](MCP-Security-Best-Practices/06-local-servers-and-supply-chain.md) → [Human approval](MCP-Security-Best-Practices/01-principles-and-threat-model.md#human-control-and-consent)
- **Operating MCP in production:** [Deployment](MCP-Security-Best-Practices/07-deployment-and-runtime.md) → [Monitoring and incident response](MCP-Security-Best-Practices/08-monitoring-and-incident-response.md) → [Testing](MCP-Security-Best-Practices/09-testing-and-review-checklists.md)
- **Reviewing an implementation:** Use the [release checklist](MCP-Security-Best-Practices/09-testing-and-review-checklists.md#release-gate-checklist) and [threat scenarios](MCP-Security-Best-Practices/01-principles-and-threat-model.md#minimum-threat-scenarios).

## Guide

1. [Security principles and threat model](MCP-Security-Best-Practices/01-principles-and-threat-model.md)
   - [Defense in depth](MCP-Security-Best-Practices/01-principles-and-threat-model.md#defense-in-depth)
   - [Fail securely](MCP-Security-Best-Practices/01-principles-and-threat-model.md#fail-securely)
   - [Zero trust](MCP-Security-Best-Practices/01-principles-and-threat-model.md#zero-trust)
   - [Trust boundaries and threat scenarios](MCP-Security-Best-Practices/01-principles-and-threat-model.md#trust-boundaries)
2. [Identity, authentication, and authorization](MCP-Security-Best-Practices/02-identity-and-authorization.md)
   - [OAuth requirements](MCP-Security-Best-Practices/02-identity-and-authorization.md#oauth-for-remote-http-servers)
   - [Token validation and passthrough](MCP-Security-Best-Practices/02-identity-and-authorization.md#validate-every-access-token)
   - [Scopes, step-up, and confused deputy](MCP-Security-Best-Practices/02-identity-and-authorization.md#authorization-model)
3. [Tools, prompts, resources, and content security](MCP-Security-Best-Practices/03-tools-and-content-security.md)
   - [Input validation](MCP-Security-Best-Practices/03-tools-and-content-security.md#validate-tool-inputs)
   - [Injection and output handling](MCP-Security-Best-Practices/03-tools-and-content-security.md#treat-all-returned-content-as-untrusted)
   - [Tool poisoning, collisions, and rug pulls](MCP-Security-Best-Practices/03-tools-and-content-security.md#tool-definition-integrity)
   - [Safe command, SQL, and URL handling](MCP-Security-Best-Practices/03-tools-and-content-security.md#dangerous-sinks)
4. [Transport, network, and protocol security](MCP-Security-Best-Practices/04-transport-and-network.md)
   - [Streamable HTTP](MCP-Security-Best-Practices/04-transport-and-network.md#streamable-http)
   - [stdio](MCP-Security-Best-Practices/04-transport-and-network.md#stdio)
   - [SSRF, DNS rebinding, CORS, retries, and versions](MCP-Security-Best-Practices/04-transport-and-network.md#outbound-request-and-ssrf-defense)
5. [Secrets, data protection, and privacy](MCP-Security-Best-Practices/05-secrets-data-and-privacy.md)
   - [Credential isolation](MCP-Security-Best-Practices/05-secrets-data-and-privacy.md#credential-isolation)
   - [Data minimization and redaction](MCP-Security-Best-Practices/05-secrets-data-and-privacy.md#data-minimization)
   - [Encryption and retention](MCP-Security-Best-Practices/05-secrets-data-and-privacy.md#storage-retention-and-deletion)
6. [Local servers and software supply chain](MCP-Security-Best-Practices/06-local-servers-and-supply-chain.md)
   - [Safe installation and process launch](MCP-Security-Best-Practices/06-local-servers-and-supply-chain.md#safe-local-server-installation)
   - [Pinning, signatures, SBOMs, and provenance](MCP-Security-Best-Practices/06-local-servers-and-supply-chain.md#dependency-and-artifact-controls)
   - [Server inventory and change control](MCP-Security-Best-Practices/06-local-servers-and-supply-chain.md#inventory-and-governance)
7. [Deployment and runtime hardening](MCP-Security-Best-Practices/07-deployment-and-runtime.md)
   - [Sandboxing and least privilege](MCP-Security-Best-Practices/07-deployment-and-runtime.md#sandboxing-and-least-privilege)
   - [Rate, resource, and egress limits](MCP-Security-Best-Practices/07-deployment-and-runtime.md#resource-and-cost-controls)
   - [Multi-tenant isolation and resilience](MCP-Security-Best-Practices/07-deployment-and-runtime.md#tenant-isolation)
8. [Monitoring and incident response](MCP-Security-Best-Practices/08-monitoring-and-incident-response.md)
   - [Security event schema](MCP-Security-Best-Practices/08-monitoring-and-incident-response.md#what-to-record)
   - [Detection ideas](MCP-Security-Best-Practices/08-monitoring-and-incident-response.md#high-value-detections)
   - [Incident playbooks](MCP-Security-Best-Practices/08-monitoring-and-incident-response.md#incident-playbooks)
9. [Testing and review checklists](MCP-Security-Best-Practices/09-testing-and-review-checklists.md)
   - [Automated and adversarial tests](MCP-Security-Best-Practices/09-testing-and-review-checklists.md#security-test-program)
   - [Release gate](MCP-Security-Best-Practices/09-testing-and-review-checklists.md#release-gate-checklist)
   - [Client, server, and operator checklists](MCP-Security-Best-Practices/09-testing-and-review-checklists.md#role-specific-checklists)
10. [References and source notes](MCP-Security-Best-Practices/10-references.md)

## Non-negotiable baseline

1. Treat the model as an untrusted planner, not a security principal or policy engine.
2. Authenticate connections and authorize **every** tool/resource operation against the verified user, client, tenant, and arguments.
3. Validate structured input with closed schemas; never concatenate model-controlled values into shells, SQL, paths, URLs, or templates.
4. Treat tool definitions, annotations, prompts, resources, errors, and results as untrusted content.
5. Keep MCP tokens out of model context and never pass an MCP bearer token to an upstream API.
6. Namespace tools by server identity, reject collisions, pin manifests, and require reapproval after meaningful changes.
7. Sandbox local servers, strip inherited secrets, restrict egress, and run without root privileges.
8. Require clear, argument-aware human approval for sensitive, external, destructive, costly, or irreversible actions.
9. Log security decisions and definition changes without logging credentials or sensitive payloads.
10. Fail closed, limit retries and agent loops, and maintain a tested revocation and incident-response path.

## Scope and terminology

- **Host/client:** The application that connects to MCP servers and exposes capabilities to a model.
- **Server:** The component exposing MCP tools, resources, or prompts.
- **Tool:** An action the model may request. A tool call is a security-sensitive delegated operation.
- **Remote server:** An MCP server reached using Streamable HTTP.
- **Local server:** Usually a subprocess connected using stdio. “Local” is not synonymous with “trusted.”
- **Deterministic control:** Code or policy evaluated outside the model. Model instructions alone are not an authorization boundary.

This is engineering guidance, not a compliance certification. Adapt it to your data classification, threat model, applicable law, and risk tolerance.

## Contributing

Add a source to [References](MCP-Security-Best-Practices/10-references.md).

## [License](LICENSE.txt).

# mcp-security-best-practices
