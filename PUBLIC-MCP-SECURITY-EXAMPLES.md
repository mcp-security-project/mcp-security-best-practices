# Public MCP Servers: Security Practice Examples

This document applies this repository's security baseline to a selection of widely visible public MCP servers. It is an evidence-based snapshot, not a certification, endorsement, or complete code audit. A server can have useful built-in controls and still be unsafe when deployed with broad credentials, weak host approval, unrestricted egress, or sensitive data in the same agent context.

**Reviewed:** 2026-10-07

## Rating key

- ✅ **Demonstrated:** the public implementation or vendor documentation shows a control aligned with the baseline.
- ⚠️ **Deployment-dependent:** the control must be supplied or correctly configured by the MCP host, operator, identity provider, network, or downstream service.
- ❌ **Gap / do not approve as-is:** a documented default, maintenance state, or missing control conflicts with the baseline for production use.

The ratings concern specific documented controls, not the overall trustworthiness of a publisher. Reassess the exact version, digest, tool manifest, configuration, and credentials before use.

## Assessment method

Each server is reviewed across the same six dimensions:

1. **Identity and authorization:** how the caller is authenticated, whether authorization is enforced per user and operation, and whether credentials can be narrowly scoped.
2. **Capability exposure:** whether operators can select exact tools, begin read-only, and keep dangerous generic tools disabled.
3. **Data boundary:** what data the server can read, what it returns to the model, and whether tenant, project, repository, page, channel, or path boundaries are enforced.
4. **Side effects and approval:** which operations create, modify, publish, delete, spend, deploy, or communicate externally, and where deterministic approval is required.
5. **Untrusted-content path:** whether issues, pages, messages, documentation, web pages, telemetry, or other user-controlled content can inject instructions into the agent.
6. **Operational assurance:** maintenance status, artifact pinning, sandboxing, egress limits, auditability, revocation, and secure defaults.

The decision labels mean:

- **Approve:** reasonable for the stated narrow use after normal version, identity, and configuration verification.
- **Conditionally approve:** useful controls exist, but the listed deployment conditions are mandatory.
- **High risk:** isolate the server and require stronger review because its purpose inherently crosses important trust boundaries.
- **Reject as-is:** do not deploy the reviewed server or default configuration in production.

## At-a-glance assessment

1. **GitHub MCP Server — conditionally approve.** Strong read-only, tool-filtering, scope, and prompt-injection-reduction options are publicly documented. Approval still depends on narrow credentials, selected tools, host confirmation for writes, and isolation from untrusted content.
2. **Filesystem reference server — conditionally approve for a sandboxed local deployment.** Allowed-directory enforcement and accurate tool annotations are good examples. Write tools, local process privileges, and the selected directories still determine the blast radius.
3. **Microsoft Playwright MCP — high risk; approve only in an isolated browser environment.** It has useful isolation and filesystem controls, but browser automation can act through authenticated sessions and its origin options are explicitly not security boundaries.
4. **Slack MCP Server — conditionally approve with minimal OAuth scopes.** Granular read/write scopes, user consent, app eligibility controls, and audit logs are good public examples. Slack content remains untrusted and potentially highly sensitive.
5. **Archived PostgreSQL reference server — reject for production.** A read-only transaction is a useful defense, but the server accepts arbitrary SQL and the repository is archived with no security guarantees.
6. **Fetch reference server — reject for production unless independently contained and verified.** Respecting `robots.txt` and limiting returned content are useful controls, but publicly tracked SSRF hardening was not present in the reviewed release.
7. **Context7 MCP — approve for public-documentation lookup with query redaction.** Its small read-only tool surface is a strong least-functionality example. Queries still leave the local trust boundary and retrieved documentation is untrusted.
8. **Notion MCP — conditionally approve, preferably read-only.** Per-user OAuth, existing Notion permissions, and enterprise client/tool controls are useful. Workspace permissions may expose broad page trees, and the service includes create/update tools.
9. **Atlassian MCP Server — conditionally approve per product and permission group.** OAuth 2.1, site binding, product scopes, and existing Jira/Confluence permissions provide layered controls. Broad cross-product access and write scopes substantially increase impact.
10. **Sentry MCP — approve for project-scoped inspection; conditionally approve other skills.** OAuth, project path constraints, read-only inspection skills, and fail-closed grants are strong patterns. Production events can contain secrets and customer data.
11. **Linear MCP — approve through its read-only endpoint; conditionally approve writes.** The dedicated read-only endpoint and read-scoped tokens provide deterministic restriction. The default endpoint is read-write and issue content is untrusted.
12. **AWS API MCP Server — high risk; conditionally approve only with narrow IAM.** A read-only mode exists, but it is not the default and IAM is the actual boundary. Even read-classified AWS operations can reveal credentials or sensitive configuration.

## 1. GitHub MCP Server

Public project: [github/github-mcp-server](https://github.com/github/github-mcp-server)

**Decision:** Conditionally approve in read-only and lockdown modes with exact tools and repository-scoped credentials. Review write access as a separate deployment profile.

### Marks

- ✅ **Least functionality:** operators can select exact tools or toolsets and can exclude tools.
- ✅ **Read-only enforcement:** read-only mode is documented as a strict filter that disables write tools even when another setting requests them.
- ✅ **Credential-aware authorization:** classic PAT scopes filter tools; remote OAuth uses scope challenges; GitHub's API still enforces credential permissions.
- ✅ **Injection risk reduction:** lockdown mode filters public-repository content from users without push access.
- ⚠️ **Lockdown is not an authorization boundary:** GitHub explicitly describes it as a best-effort content filter. Other tools or direct API access may still expose content available to the credential.
- ⚠️ **Fine-grained PAT and GitHub App tools are not pre-filtered by discovered scopes:** all tools may be shown while the GitHub API enforces permissions.
- ⚠️ **Human approval is still a host responsibility:** issue comments, merges, workflow actions, and other writes need argument-aware confirmation.
- ⚠️ **Supply-chain controls remain external:** pin the binary or image by version and digest; do not auto-run a mutable package version.

### Threat path

An attacker places instructions in a public issue, pull-request description, review comment, or repository file. The agent reads that content, treats it as trusted workflow direction, and uses an enabled tool to disclose private repository data, alter code, approve a pull request, or start a workflow. Lockdown can reduce exposure to some public content, but it cannot prove that content in an authorized repository is trustworthy.

### Safer public-environment example

Use a dedicated identity limited to the required repositories. Start with:

```text
GITHUB_READ_ONLY=1
GITHUB_LOCKDOWN_MODE=1
GITHUB_TOOLSETS=repos,issues
```

Then narrow the enabled tools further, inject the token from a secret manager, and keep write capability in a separate server profile that always requires confirmation. Do not place the token in a checked-in MCP configuration file or model-visible prompt.

Evidence: [server configuration](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md), [scope filtering](https://github.com/github/github-mcp-server/blob/main/docs/scope-filtering.md), and [Streamable HTTP guidance](https://github.com/github/github-mcp-server/blob/main/docs/streamable-http.md).

## 2. Filesystem reference server

Public project: [modelcontextprotocol/servers — Filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)

**Decision:** Conditionally approve as a local server only when the allowed root is purpose-specific, the process is sandboxed, and write tools are disabled or separately approved.

### Marks

- ✅ **Server-side path scope:** operations are limited to configured allowed directories, with dynamic updates supported through MCP Roots.
- ✅ **Risk metadata:** read tools use `readOnlyHint`; write operations identify idempotent and destructive behavior; tools use `openWorldHint: false`.
- ✅ **Narrower than unrestricted host access:** an explicit directory boundary is materially better than exposing the user's home directory or entire workspace.
- ⚠️ **Annotations are hints, not enforcement:** the client must not auto-approve solely because an annotation claims an operation is safe.
- ⚠️ **Configured roots define the blast radius:** selecting `/`, a home directory, credential stores, source-control metadata, or shared secrets defeats least privilege.
- ⚠️ **Write tools need confirmation:** overwrite, move, and delete operations require target-aware approval and bounded retries.
- ⚠️ **Local execution needs a sandbox:** allowed directories do not replace OS-level process, environment, network, and resource restrictions.

### Threat path

Untrusted repository text tells the agent to inspect a neighboring credential file or overwrite a configuration file. If the configured root is the entire workspace or home directory, the request may remain inside the nominal allowed boundary while still violating user intent. A later cross-server call can transmit the file contents externally.

### Safer public-environment example

Run a pinned artifact as a dedicated low-privilege user with:

- one purpose-specific mounted directory, read-only where possible;
- no inherited cloud, Git, SSH, package-registry, or shell credentials;
- no network access;
- a private, size-limited temporary directory;
- CPU, memory, process, file-size, and execution-time limits; and
- host confirmation for every mutation.

For example, expose `/workspace/docs` rather than `/workspace`, and use a separate write-capable profile only for workflows that genuinely need changes. Treat Roots as configuration input that the server validates, not as a client-side security guarantee.

Evidence: [Filesystem server documentation](https://github.com/modelcontextprotocol/servers/blob/main/src/filesystem/README.md) and the repository's warning that reference servers are educational rather than production-ready in [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers).

## 3. Microsoft Playwright MCP

Public project: [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)

**Decision:** High risk. Approve only for an ephemeral, non-personal browser with network enforcement, no ambient credentials, and confirmation for every consequential interaction.

### Marks

- ✅ **Filesystem restriction by default:** unrestricted file access is opt-in, and `file://` navigation is blocked by default outside configured workspace roots.
- ✅ **Ephemeral browser option:** isolated mode keeps the browser profile in memory instead of persisting it.
- ✅ **Browser sandbox option:** documented configuration supports sandboxing.
- ⚠️ **All origins are allowed by default:** an operator must constrain browser egress for a narrow workflow.
- ⚠️ **Origin flags are not security boundaries:** the project explicitly warns that allow/block lists do not cover redirects and can be worked around.
- ⚠️ **Authenticated sessions amplify impact:** a click can send data, submit forms, change settings, or trigger purchases under the logged-in user's authority.
- ⚠️ **Page content is untrusted:** accessibility snapshots, text, and rendered instructions can carry prompt injection.
- ❌ **Unsafe as a general-purpose production browser with unrestricted network and user profile access.**

### Threat path

Malicious page content instructs the agent to navigate to an internal site, upload a local file, reveal authenticated content, or submit a transaction. The model sees the page instruction and has the browser capability needed to act on it. A browser origin allowlist alone does not stop redirect-based navigation or replace an enforcing egress boundary.

### Safer public-environment example

Use an ephemeral container or VM with a fresh, non-personal browser profile. Enable isolated mode and the browser sandbox, leave unrestricted file access disabled, mount no secrets, and enforce destinations at a network proxy or firewall. An origin allowlist is useful defense in depth but cannot replace network enforcement.

Separate read-only page inspection from actions. Require confirmation that displays the final origin, form fields, uploaded data, and expected effect before login, upload, submit, message, purchase, or account-setting operations.

Evidence: [Playwright MCP configuration and security notes](https://github.com/microsoft/playwright-mcp#configuration).

## 4. Slack MCP Server

Public documentation: [Slack MCP server overview](https://docs.slack.dev/ai/mcp-server)

**Decision:** Conditionally approve with per-user OAuth and only the channel/message scopes required by the workflow. Keep sending and object-management tools in a separately approved write profile.

### Marks

- ✅ **Granular OAuth scopes:** public channels, private channels, direct messages, group messages, files, users, and write operations have separate documented scopes.
- ✅ **Consent for sensitive search:** private-channel and message scopes are described as requiring user consent.
- ✅ **Restricted app classes:** Slack currently limits MCP use to internal or Marketplace-published apps.
- ✅ **Auditability:** Slack documents associated audit logs for MCP activity.
- ⚠️ **Scope selection is operator-controlled:** requesting every documented scope would violate least privilege.
- ⚠️ **Search results and messages are untrusted:** a malicious message can attempt to direct the model to exfiltrate Slack or cross-server data.
- ⚠️ **Write tools need explicit approval:** sending messages and creating or modifying Slack objects create external side effects.
- ⚠️ **Cross-server use raises exfiltration risk:** Slack itself cautions users to consider the security characteristics of other connected MCP servers.

### Threat path

An external participant posts a message asking the agent to search private channels and send the results to another channel or service. Search and send operations may each be authorized, but their composition creates an unintended confidentiality breach. Channel membership and OAuth scope checks do not validate the user's intent for that transfer.

### Safer public-environment example

Create a dedicated internal app and begin with only `search:read.public` for a public-channel search use case. Add `search:read.private`, `search:read.im`, `search:read.mpim`, file, user-email, or write scopes only after a documented need and consent review.

Keep search/read tools in a read-only profile. Put `chat:write` and object-management scopes in a separate profile with destination- and content-aware confirmation. Record the authenticated user, tool, channel/object, scope decision, and outcome without logging message bodies unnecessarily.

Evidence: [Slack MCP security and scope documentation](https://docs.slack.dev/ai/mcp-server) and [the granular search-scope announcement](https://docs.slack.dev/changelog/2026/02/17/slack-mcp).

## 5. Archived PostgreSQL reference server

Public project: [modelcontextprotocol/servers-archived — PostgreSQL](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres)

**Decision:** Reject for production because the implementation is archived and exposes arbitrary SQL. Retain only as an educational example of database-enforced read-only transactions.

### Marks

- ✅ **Database-side read-only transaction:** the `query` tool begins a `READ ONLY` transaction and rolls it back.
- ⚠️ **Read-only does not mean low risk:** arbitrary `SELECT` statements can expose credentials, personal data, tenant data, large results, or expensive query plans.
- ⚠️ **The tool accepts raw SQL:** this conflicts with the guide's preference for narrow, parameterized business tools.
- ⚠️ **Additional controls are required:** use a dedicated read-only database role, deny-by-default row-level security, statement timeout, row/result limits, and preferably a replica containing minimized data.
- ❌ **Unmaintained:** the repository is archived and states that no security guarantees, updates, or fixes are provided.
- ❌ **Do not use this archived implementation in production.**

### Threat path

The model generates a syntactically read-only query that scans a credentials table, bypasses intended tenant filtering, joins sensitive records, or consumes enough resources to affect production. The transaction prevents database mutation, but it does not enforce data minimization, row-level authorization, query cost, or safe disclosure to the model.

### Better replacement pattern

Replace a generic `query(sql)` tool with narrow operations such as `orders.get_status(order_id)` or `support.search_tickets(query, limit)`. Parameterize values, derive tenant identity from verified authentication, cap results and execution time, and expose only approved columns or views. Keep the database credential read-only even when application logic also enforces read-only behavior.

Evidence: [archived server notice](https://github.com/modelcontextprotocol/servers-archived/blob/main/README.md), [PostgreSQL server documentation](https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres), and [read-only transaction implementation](https://github.com/modelcontextprotocol/servers-archived/blob/main/src/postgres/index.ts).

## 6. Fetch reference server

Public project: [modelcontextprotocol/servers — Fetch](https://github.com/modelcontextprotocol/servers/tree/main/src/fetch)

**Decision:** Reject the reviewed release for normal production networks. Reconsider only after verified SSRF remediation or deployment behind an egress proxy that enforces destination policy independently.

### Marks

- ✅ **Autonomous-use identification:** model-initiated and user-initiated requests use distinguishable default user agents.
- ✅ **Robots policy:** model-initiated fetches respect `robots.txt` by default.
- ✅ **Basic result bound:** the tool provides a maximum returned-content length.
- ⚠️ **Arbitrary fetched content is untrusted:** returned pages can contain prompt injection, malicious links, oversized decompressed data, or sensitive material.
- ❌ **SSRF gap in the reviewed release:** public issue and pull-request records report missing scheme/address restrictions and redirect revalidation, allowing access attempts toward loopback, private, link-local, or cloud metadata endpoints.
- ❌ **Do not rely on** `robots.txt` **as a network security control.**
- ❌ **Do not deploy the reviewed release in a network that can reach internal services or metadata endpoints without an enforcing egress layer.**

### Threat path

Untrusted content supplies a URL that appears public but resolves or redirects to loopback, a private service, or a cloud metadata address. The server fetches the target and returns internal data to the model. Separately, even a legitimate public page can contain prompt injection that influences later calls to sensitive servers.

### Safer public-environment example

Prefer a purpose-specific fetch tool with an exact HTTPS hostname allowlist. Route it through an egress proxy that blocks private, loopback, link-local, reserved, and metadata ranges; resolves and pins validated addresses; and revalidates every redirect. Limit ports, methods, redirects, response bytes, decompression ratio, content types, and time.

Until an SSRF fix is merged, released, and independently verified, package configuration alone is insufficient. If fetching arbitrary public sites is necessary, place the server in a disposable network zone with no internal routes, no cloud metadata access, and no ambient credentials.

Evidence: [Fetch server documentation](https://github.com/modelcontextprotocol/servers/blob/main/src/fetch/README.md), [SSRF tracking issue](https://github.com/modelcontextprotocol/servers/issues/3741), and [public hardening proposal](https://github.com/modelcontextprotocol/servers/pull/4497). Verify their current status before making a deployment decision.

## 7. Context7 MCP

Public project: [upstash/context7](https://github.com/upstash/context7)

**Decision:** Approve for retrieving public documentation when queries are redacted and returned content is treated as untrusted. Reassess separately before connecting private documentation sources.

### Marks

- ✅ **Small, read-only capability surface:** the public MCP interface primarily resolves library identifiers and retrieves documentation. It does not need repository write access or code-execution privileges for this use case.
- ✅ **Hosted authentication options:** the remote service supports OAuth or an API key, while anonymous access is also documented with lower rate limits.
- ✅ **Documented data flow:** Context7 states that the formulated query and library identifier are sent to its API rather than the full prompt, source tree, or conversation.
- ⚠️ **Query text crosses the trust boundary:** model-generated search terms can still contain proprietary names, code fragments, credentials, customer information, or details inferred from the conversation.
- ⚠️ **Redaction instructions are not enforcement:** a tool description telling the model to remove secrets cannot guarantee that it will do so. The host should apply deterministic secret and sensitive-data detection before transmission.
- ⚠️ **Retrieved documentation is untrusted:** public repositories, websites, uploaded files, and private sources may contain prompt injection or unsafe code examples.
- ⚠️ **Hosted-service assurance is partial:** the MCP source is public, but Context7 documents that supporting backend, parsing, and crawling components are private.
- ⚠️ **API keys need normal secret handling:** never embed a Context7 key in a repository-level configuration or prompt. Prefer OAuth or secret-store injection.

### Threat path

A developer asks for help with proprietary code. The model constructs a documentation query containing an internal class name, a partial stack trace, or a credential copied from nearby context. That query is sent to the hosted service. Returned documentation then includes text telling the agent to run a command or disclose more context. Read-only access prevents direct mutation, but it does not prevent confidentiality loss or influence over later tool calls.

### Safer public-environment example

Use the hosted OAuth endpoint or inject an API key from a user secret store. Permit only the two documentation tools. Before invocation, reduce the request to a public library name, public version, and generic technical question; reject likely secrets, email addresses, internal hostnames, customer identifiers, and substantial source-code excerpts.

Keep Context7 in a read-only research context that has no production credentials or deployment tools. Parse returned material as reference data, do not automatically execute commands from it, and require review before adding retrieved dependencies or copying security-sensitive configuration.

Evidence: [Context7 MCP tools and setup](https://github.com/upstash/context7/blob/master/README.md), [installation and authentication](https://upstash-context7.mintlify.app/installation), and [data privacy documentation](https://context7.mintlify.app/security/data-privacy).

## 8. Notion MCP

Public documentation: [Notion MCP overview](https://developers.notion.com/guides/mcp/overview)

**Decision:** Conditionally approve per user with the smallest accessible page tree and read-only tools where supported. Require explicit confirmation for page, database, and comment mutations.

### Marks

- ✅ **Per-user delegated identity:** Notion's hosted MCP uses OAuth and acts with the authorizing user's existing Notion permissions rather than a shared workspace-wide integration credential.
- ✅ **Modern OAuth client requirements:** Notion documents authorization-code flow, mandatory PKCE, state validation, token refresh, and secure credential storage.
- ✅ **Existing access controls remain active:** MCP does not bypass Notion page and workspace permissions.
- ✅ **Enterprise governance:** administrators can allowlist MCP clients and block tools that are not explicitly approved; organization controls can list and revoke connections.
- ✅ **Conditional tool exposure:** the server advertises tools available to the connection and plan rather than assuming every capability is usable.
- ⚠️ **Authorization may still be broad:** a user can legitimately read large portions of a workspace. Existing permission does not mean all accessible content is necessary for the agent's task.
- ⚠️ **Page-tree inheritance increases blast radius:** access to a parent page can expose descendants, linked databases, comments, and embedded operational knowledge.
- ⚠️ **Write capabilities are material:** tools can create and update pages and databases. Mistakes can publish misleading information, alter workflows, or overwrite shared knowledge.
- ⚠️ **Notion content is untrusted:** shared pages, imported documents, comments, and connected-source results can contain prompt injection.
- ⚠️ **Revocation must be operationally tested:** administrators need a procedure for disconnecting users and blocking previously authorized clients.

### Threat path

An agent searches an incident-response workspace and retrieves a page containing pasted external text. That text instructs the agent to summarize secrets into a new public page. Because the same MCP connection can both read and write, a single injected instruction may bridge sensitive content into an externally visible artifact.

### Safer public-environment example

Use a dedicated user or workspace area containing only the pages needed for the workflow. Enterprise deployments should allowlist the approved MCP client and approved tools. Keep search/read in the default profile and place create/update tools in a separate profile with previews.

Before a write, show the target workspace, parent page or database, visibility, fields, full content, and whether existing content will be replaced. Bind approval to those normalized arguments and expire it after one use. Log object identifiers and decisions, but avoid duplicating page contents in audit logs.

Evidence: [Notion MCP overview](https://developers.notion.com/guides/mcp/overview), [client and OAuth requirements](https://developers.notion.com/guides/mcp/build-mcp-client), [supported tools](https://developers.notion.com/guides/mcp/mcp-supported-tools), and [enterprise MCP controls](https://www.notion.com/help/notion-mcp).

## 9. Atlassian MCP Server

Public project: [atlassian/atlassian-mcp-server](https://github.com/atlassian/atlassian-mcp-server)

**Decision:** Conditionally approve with OAuth 2.1 for a specific Atlassian site, selected products, and read/search permission groups. Approve write groups only for a defined workflow with confirmation.

### Marks

- ✅ **OAuth 2.1 for interactive users:** the official remote server supports delegated authorization without handing a user's password to the MCP client.
- ✅ **Site and user binding:** Atlassian documents enforcement of the user's existing product permissions and validation against the correct `cloudId`.
- ✅ **Product-level capability groups:** Jira and Confluence expose separate read, write, and search permissions; other products document their own read/write groups.
- ✅ **Transport and network controls:** Atlassian documents HTTPS with TLS 1.2 or later and enforcement of configured Atlassian IP allowlists.
- ✅ **Administrative and audit controls:** the official guidance recommends least privilege, review of high-impact changes, and audit-log monitoring.
- ⚠️ **One endpoint spans many systems:** Jira, Confluence, Jira Service Management, Bitbucket, Compass, Loom, and platform data have different sensitivity and side effects.
- ⚠️ **Existing user access may be excessive for an agent:** project administrators and support staff often have broad access across tickets, private spaces, customer attachments, and source repositories.
- ⚠️ **API-token mode shifts responsibility to the operator:** tokens must be scoped, stored, rotated, and mapped to a distinct user or service account. Jira Service Management and Bitbucket have documented authentication limitations.
- ⚠️ **Write groups are coarse:** permission to write can cover issue changes, comments, pages, service-management records, or other shared artifacts.
- ⚠️ **Cross-product search magnifies injection and leakage risk:** a malicious ticket or page can influence actions in another connected Atlassian product.

### Threat path

A support ticket contains attacker-authored instructions. The agent reads it through Jira Service Management, searches Confluence for internal remediation steps, and then posts sensitive excerpts to a public Jira issue or modifies a Bitbucket object. Every individual API action may be authorized for the user, while the end-to-end data flow violates intent.

### Safer public-environment example

Prefer per-user OAuth over a shared API token. Authorize one site and only the product permission groups required by the workflow—for example, Jira `read` and `search` without Jira `write`, Confluence, Bitbucket, or platform-wide search.

For a write workflow, use a dedicated service account limited to named projects or spaces. Require a preview showing product, site, project/space, object, visibility, content, and side effects. Enforce cross-product information-flow policy rather than assuming that access to both systems permits automatic transfer between them.

Evidence: [official server documentation](https://github.com/atlassian/atlassian-mcp-server/blob/HEAD/README.md), [getting started and security guidance](https://support.atlassian.com/atlassian-ai-gateway/docs/get-started-with-the-atlassian-remote-mcp-server/), and [OAuth 2.1 configuration](https://support.atlassian.com/atlassian-ai-gateway/docs/configure-oauth-2-1/).

## 10. Sentry MCP

Public project: [getsentry/sentry-mcp](https://github.com/getsentry/sentry-mcp)

**Decision:** Approve the hosted service for a project-scoped, `inspect`-only debugging workflow after data-classification review. Conditionally approve triage or project-management skills.

### Marks

- ✅ **OAuth for hosted connections:** clients do not need direct Sentry API tokens for the normal hosted flow.
- ✅ **Resource constraints:** the MCP URL can be bound to one organization or one project, and the constraint is enforced on each request.
- ✅ **Capability bundles:** the `inspect` skill is read-only; triage and project-management skills are separate and disabled by default in the documented implementation.
- ✅ **Reduced discovery:** organization/project path constraints hide unnecessary discovery tools.
- ✅ **Layered authorization:** Sentry documents upstream scopes, MCP skills, and resource constraints as separate restrictions.
- ✅ **Fail-closed grant handling:** stale or invalid grants are revoked or require reauthentication, and refresh does not widen the original grant.
- ⚠️ **Observability data is frequently sensitive:** stack traces, request data, breadcrumbs, replay data, tags, release metadata, and profiles can contain credentials, personal data, internal URLs, or source details.
- ⚠️ **Read-only output can still cause compromise:** a model may expose a secret found in an event or follow attacker-controlled text captured in an exception or user input.
- ⚠️ **Direct bearer mode has broader defaults:** Sentry documents that direct `Sentry-Bearer` sessions default to all active skills unless narrowed.
- ⚠️ **Triage and management mutate production operations:** resolving, assigning, creating projects, changing teams, or managing monitors requires confirmation and audit.

### Threat path

An attacker places prompt text in an HTTP parameter that is captured by a production error. The agent retrieves the event to diagnose an issue, treats the captured text as instructions, then uses a coding, messaging, or issue-management server to send Sentry data elsewhere.

### Safer public-environment example

Connect to the most specific project URL and request only the `inspect` skill:

```text
https://mcp.sentry.dev/mcp/your-organization/your-project?skills=inspect
```

Disable experimental features. Apply secret and personal-data redaction before results enter model context, and prevent automatic transfer to other servers. If triage is required, add only the triage skill and confirm the exact issue, new state, assignee, and comment. Avoid direct bearer authentication unless OAuth is unavailable; if it is necessary, explicitly narrow skills.

Evidence: [Sentry MCP documentation](https://docs.sentry.io/product/sentry-mcp/), [hosted service setup](https://mcp.sentry.dev/), [skill definitions](https://github.com/getsentry/sentry-mcp/blob/main/packages/mcp-core/src/skills.ts), and [authorization architecture](https://github.com/getsentry/sentry-mcp/blob/main/docs/operations/security.md).

## 11. Linear MCP

Public documentation: [Linear MCP server](https://linear.app/docs/mcp)

**Decision:** Approve the dedicated read-only endpoint or an OAuth/API credential restricted to read. Conditionally approve narrowly scoped issue or comment creation; avoid broad default write access.

### Marks

- ✅ **Dedicated read-only endpoint:** `/mcp/readonly` exposes only read tools, providing a deterministic capability boundary.
- ✅ **Credential-level read restriction:** clients can request only the `read` OAuth scope or use a read-only API key, so the underlying token cannot call write APIs.
- ✅ **OAuth 2.1 hosted flow:** Linear documents Streamable HTTP, dynamic client registration, and interactive authorization.
- ✅ **Narrow write scopes exist:** Linear documents scopes such as issue creation and comment creation separately from general write and admin access.
- ⚠️ **The default endpoint is read-write:** connecting to `/mcp` without deliberately restricting scopes exposes tools for creating and updating Linear objects.
- ⚠️ **User authorization inherits broad workspace access:** a token can act across the teams and objects available to the authorizing identity.
- ⚠️ **Issue and comment text is untrusted:** customer reports, copied logs, webhook content, and external links can contain prompt injection.
- ⚠️ **Mutations are externally visible:** status changes, assignments, comments, project updates, and issue creation affect shared planning and may trigger notifications or automations.
- ❌ **Admin scope is inappropriate for routine agent use.**

### Threat path

An agent reads an attacker-controlled issue description that asks it to close related issues and post internal debugging details as comments. With the default read-write endpoint, those actions may be available in the same context and execute under the user's authority.

### Safer public-environment example

Use:

```text
https://mcp.linear.app/mcp/readonly
```

For a bot that must create issues, use a separate credential restricted to selected teams and the issue-creation permission rather than general write or admin. Show the team, project, title, labels, assignee, description, and notification effects before creation. Do not automatically copy raw content from Slack, Sentry, support systems, or public pages into Linear.

Evidence: [Linear MCP server documentation](https://linear.app/docs/mcp) and [Linear OAuth scopes and PKCE](https://linear.app/developers/oauth-2-0-authentication).

## 12. AWS API MCP Server

Public project: [awslabs/mcp — AWS API MCP Server](https://github.com/awslabs/mcp/tree/main/src/aws-api-mcp-server)

**Decision:** High risk. Conditionally approve only in a dedicated AWS account or tightly bounded role with `READ_OPERATIONS_ONLY=true`, explicit command/service restrictions, no ambient developer credentials, and CloudTrail monitoring. Do not expose administrator credentials.

### Marks

- ✅ **Optional read-only filter:** `READ_OPERATIONS_ONLY=true` blocks operations classified as write by AWS service authorization metadata.
- ✅ **AWS identifies IAM as the primary boundary:** this is the correct model—an application flag is defense in depth, not a substitute for resource-level authorization.
- ✅ **Auditing is available:** AWS API calls can be monitored through CloudTrail, with a distinct role or session identity.
- ✅ **Deployment guidance recommends custom IAM:** documented controls include service/resource restrictions and conditions for region, time, and resource tags.
- ⚠️ **Read-only mode is not the documented default:** `READ_OPERATIONS_ONLY` defaults to false, so an operator must deliberately enable it.
- ⚠️ **Generic API execution is a dangerous tool shape:** a broad `call_aws` capability exposes a large and evolving command surface rather than narrow business operations.
- ⚠️ **AWS “read” is not equivalent to non-sensitive:** documented read operations may return credentials, secrets, configuration, resource policies, customer data, or presigned access material.
- ⚠️ **Some read-classified actions can write locally:** the project warns that read-only classification concerns AWS APIs, not filesystem side effects.
- ⚠️ **Shared runtime roles obscure end-user authorization:** a remote deployment using one execution role needs a separate deterministic policy mapping each verified user to allowed services, actions, regions, accounts, and resources.
- ⚠️ **Additional telemetry is enabled by default:** operators should review the documented telemetry behavior against privacy requirements.
- ❌ **Administrator, PowerUser, or broad wildcard IAM policies are not acceptable for agent use.**

### Threat path

An agent reads untrusted issue or web content instructing it to inspect an AWS secret, invoke a credential-returning read API, or enumerate production infrastructure. The request passes the server's read-only classifier, and the broad IAM role permits it. The resulting credentials or configuration enter model context and can then be exfiltrated through another tool.

### Safer public-environment example

Create a dedicated role for one account and workflow. Deny all actions by default; allow only named read actions on named resources with region, account, tag, and organization conditions. Add explicit denies for Secrets Manager secret values, SSM secure parameters, credential vending, data-plane reads, and other sensitive APIs even if AWS classifies them as read.

Set `READ_OPERATIONS_ONLY=true`, disable unnecessary telemetry where policy requires it, strip inherited AWS environment variables, and run the server in an isolated process. Require confirmation for costly reads, broad enumeration, credential-related operations, or access to production. Alert on denied calls, new services, unusual regions, and attempts to access secrets.

Prefer the [AWS Documentation MCP Server](https://github.com/awslabs/mcp/tree/main/src/aws-documentation-mcp-server) or the unauthenticated [AWS Knowledge MCP Server](https://github.com/awslabs/mcp/tree/main/src/aws-knowledge-mcp-server) when the task only needs public AWS documentation; neither requires the production AWS permissions needed by the API server.

Evidence: [AWS API MCP Server documentation](https://github.com/awslabs/mcp/blob/main/src/aws-api-mcp-server/README.md), [deployment security guidance](https://github.com/awslabs/mcp/blob/main/src/aws-api-mcp-server/DEPLOYMENT.md), and [AWS Documentation MCP Server](https://github.com/awslabs/mcp/blob/main/src/aws-documentation-mcp-server/README.md).

## Reusable approval record

For any public MCP server, record the deployment decision in a form similar to:

```yaml
server:
  identity: verified-publisher-and-server-name
  version: exact-version
  artifact_digest: sha256:verified-digest
  transport: stdio-or-https-endpoint
  tools: [exact, approved, tool_names]
  credential_scope: documented-least-privilege-scope
  filesystem: [exact-approved-roots]
  egress: [exact-approved-hosts-and-ports]
  data_classes: [public, internal]
  human_approval: [all-writes, sensitive-reads, cross-server-data-flow]
  sandbox: enabled
  audit_owner: team-name
  review_expires: 2027-01-07
```

Reject or quarantine the server when its artifact digest, publisher, endpoint, tool names, schemas, annotations, requested permissions, destinations, or side effects change. Registry presence and a familiar publisher name do not replace this review.

## Minimum checks before enabling a public MCP

- Verify the official publisher link and pin the exact artifact and digest.
- Review the current maintenance and vulnerability status; do not rely on this dated snapshot.
- Diff and approve the tool manifest; namespace tools by authenticated server identity.
- Start read-only with exact tool and resource allowlists.
- Use a dedicated, least-privilege credential; never expose it to model context.
- Sandbox local processes and default-deny filesystem, environment, and network access.
- Treat every tool description, annotation, resource, prompt, error, and result as untrusted.
- Require argument-aware confirmation for sensitive reads, writes, external actions, and cross-server transfers.
- Apply time, size, rate, concurrency, retry, and cost limits.
- Log authorization and approval decisions without recording secrets or unnecessary payloads.
- Test revocation, disablement, credential rotation, and rollback before production use.

