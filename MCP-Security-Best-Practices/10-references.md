# 10. References and Source Notes

[← Testing and checklists](09-testing-and-review-checklists.md) | [README](../README.md)

Research cutoff: **2026-09-27**. Prefer the pinned MCP version below for reproducibility; review the latest released specification before implementation.

## Normative MCP sources

- [MCP Specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) — released protocol baseline.
- [Key Changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog) — stateless change and removed/deprecated features.
- [Versioning and Compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning).
- [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
- [Authorization Server Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery).
- [Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration).
- [Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations).
- [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).
- [stdio Transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio).
- [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
- [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation).
- [Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) — deprecated in 2026-07-28.
- [Sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling) — deprecated in 2026-07-28.
- [SEP-2577: Deprecate Roots, Sampling, and Logging](https://modelcontextprotocol.io/seps/2577-deprecate-roots-sampling-and-logging).
- [SEP-1024: Local Server Installation Security Requirements](https://modelcontextprotocol.io/seps/1024-mcp-client-security-requirements-for-local-server-).

## Official MCP implementation guidance

- [Security Best Practices, 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
- [Client Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/develop/clients/client-best-practices).
- [Official MCP Registry Requirements](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/official-registry-requirements.md).
- [Tool Integrity discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2402) — emerging, non-normative discussion.
- [Signed Tool Manifests discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2913) — emerging, non-normative discussion.

### Legacy note

The prior [2025-11-25 Security Best Practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) includes `Mcp-Session-Id` defenses for implementations that still support that protocol generation. Do not introduce protocol sessions into a new 2026-07-28 implementation.

## OAuth and internet standards

- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html).
- [OAuth 2.1 Internet-Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — required by MCP, but still a draft at this guide's cutoff.
- [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636.html).
- [RFC 8707: Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html).
- [RFC 9068: JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html).
- [RFC 9207: OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html).
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html).

## OWASP guidance

OWASP publications are respected community guidance, not formal standards or a certification. The OWASP MCP Top 10 page identifies its 2025 list as a beta/community-review project at this guide's cutoff.

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).
- [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).
- [Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/).
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/).
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/).
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html).
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
- [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

## NIST and government guidance

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final).
- [NIST SP 800-218: Secure Software Development Framework 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).
- [NIST AI 600-1: Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).
- [NIST SP 800-53 Rev. 5, Update 1](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).
- [NIST SP 800-61 Rev. 3: Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- [NIST Code Signing Guidance](https://csrc.nist.gov/pubs/cswp/5/security-considerations-for-code-signing/final).
- [CISA SBOM resources](https://www.cisa.gov/sbom).

## Supply-chain specifications

- [SLSA v1.2](https://slsa.dev/spec/v1.2/).
- [SPDX Specifications](https://spdx.dev/use/specifications/).
- [CycloneDX](https://cyclonedx.org/).

## Primary research and advisories

These sources provide threat evidence; they are not protocol standards.

- [Invariant Labs: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).
- [Invariant Labs: WhatsApp MCP Exploitation](https://invariantlabs.ai/blog/whatsapp-mcp-exploited).
- [Trail of Bits: Jumping the Line](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/).
- [Trail of Bits: Stealing Conversation History](https://blog.trailofbits.com/2025/04/23/how-mcp-servers-can-steal-your-conversation-history/).
- [Docker MCP Gateway Advisory GHSA-m5m2-mrxf-7j7q](https://github.com/docker/mcp-gateway/security/advisories/GHSA-m5m2-mrxf-7j7q).
- [Postmark: Malicious `postmark-mcp` Package](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package).
- [Snyk analysis of malicious `postmark-mcp`](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/).
- [OX Security: stdio Supply-Chain Technical Analysis](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-technical-deep-dive/).

## Major vendor guidance

Vendor guidance is authoritative for the named product or the vendor's research, not a universal standard.

- [Microsoft: Securing MCP Tool Execution](https://developer.microsoft.com/blog/securing-mcp-a-control-plane-for-agent-tool-execution/).
- [Anthropic: How We Contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude).
- [OpenAI: MCP Servers in the Responses API](https://developers.openai.com/api/docs/guides/tools-connectors-mcp).
- [Google Cloud: Secure Remote MCP Servers](https://cloud.google.com/blog/products/identity-security/how-to-secure-your-remote-mcp-server-on-google-cloud).
- [AWS: Model Context Protocol Strategies](https://docs.aws.amazon.com/prescriptive-guidance/latest/mcp-strategies/mcp-strategies.pdf).

## Evidence quality

When sources disagree:

1. Follow the applicable released MCP specification for protocol behavior.
2. Follow finalized RFCs for OAuth/internet security, while meeting MCP's additional profile.
3. Use NIST/OWASP guidance to design controls around the protocol.
4. Use advisories and primary research to update threat scenarios and tests.
5. Treat blogs, benchmarks, and preprints as evidence—not normative requirements.

Recheck links, document status, and version dates before relying on this guide for a production release.
