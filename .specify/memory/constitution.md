<!--
Sync Impact Report
==================
Version change: (unversioned template) → 1.0.0
Modified principles: ALL — initial constitution authoring from blank template placeholder tokens.

Added sections:
  - Core Principles (8 principles: Reusability First, Modularity & Separation of Concerns,
    Configuration Over Code, Provider Abstraction, Simplicity First, Security by Default,
    Observability & Cost Transparency, Test-Driven Quality)
  - Technology Stack
  - Development Philosophy & Definition of Done
  - Governance

Removed sections: None (all prior content was placeholder tokens)

Templates requiring updates:
  - .specify/templates/plan-template.md     ✅ No structural change needed — "Constitution Check"
                                               section already present as a feature-level gate.
  - .specify/templates/spec-template.md     ✅ Requirements & Success Criteria structure aligns
                                               with principles; no updates required.
  - .specify/templates/tasks-template.md    ✅ Phase structure (Setup → Foundational → Stories →
                                               Polish) aligns with observability, security, and
                                               testing task types introduced in this constitution.
  - .specify/templates/checklist-template.md ✅ Generic template; no constitution-specific
                                               updates required.

Follow-up TODOs: None — all placeholders resolved.
-->

# KnowledgeAI Constitution

## Core Principles

### I. Reusability First

Every piece of code merged into the framework MUST be demonstrably reusable across at least
two distinct client contexts. Client-specific logic MUST live in client configuration files,
not in the framework core. Each new client deployment MUST be faster and cheaper to deliver
than the previous one.

**Rationale**: KnowledgeAI is the primary commercial asset of a one-person consultancy.
Reusability is not a quality concern — it is the business model. Code that cannot serve at
least two clients has no justified place in the framework.

### II. Modularity & Separation of Concerns

Each module (auth, ingestion, retrieval, LLM, workflows, observability) MUST be independently
usable, testable, and deployable without importing other framework modules as hard dependencies.
Client code MUST NOT modify framework core — it MAY only extend or configure it through
published interfaces. No tight coupling between modules is permitted.

**Rationale**: Tight coupling forces every client to carry every module's transitive
dependencies, slows deployments, and creates unpredictable failure surfaces across the
client portfolio.

### III. Configuration Over Code

Client deployments MUST be differentiated exclusively by configuration files and environment
variables. Forking the codebase to create a client variant is PROHIBITED. Every behavior
that differs between client deployments MUST be expressible without writing or modifying
framework code.

**Rationale**: Forks create divergence that compounds with every core update and permanently
erodes the reusability dividend the framework was built to deliver.

### IV. Provider Abstraction

All LLM provider calls (OpenAI, AWS Bedrock, Anthropic, and any future provider) MUST be
routed through a single provider-agnostic interface. The same abstraction principle MUST
apply to vector stores (pgvector initially). Swapping an LLM provider or vector store MUST
require only a configuration change — no changes to business logic are permitted.

**Rationale**: SME clients have varying cloud commitments and cost constraints. Provider
lock-in embedded in the framework would force re-implementation work on every client
migration, destroying the reusability model.

### V. Simplicity First

Plain Python MUST be the default implementation choice for all workflows. Orchestration
frameworks (LangGraph, Prefect, Airflow, etc.) MUST only be introduced when state management
or complex branching genuinely cannot be handled with standard Python control flow. Every
new dependency MUST be justified by a real, present constraint — not an anticipated future
need. YAGNI applies unconditionally.

**Rationale**: Simple code is easier to debug, cheaper to operate, and faster to evolve
for a solo operator. Over-engineering a solo-maintained framework increases carrying cost
without delivering client value.

### VI. Security by Default

Multi-tenancy and strict data isolation between client organizations MUST be enforced at the
database layer from the first line of code — not retrofitted later. Authentication MUST be
required on every endpoint that accesses or returns client data; no public endpoints that
expose client data are permitted. All sensitive data MUST be encrypted at rest and in transit.
Audit logs MUST be written for every document access and every LLM query. No secrets,
credentials, or API keys MAY appear in source code or version control under any circumstances.

**Rationale**: A breach or data leakage event in a shared-tenant framework simultaneously
affects all active clients. Security retrofitted after launch is significantly more expensive,
more error-prone, and commercially disqualifying.

### VII. Observability & Cost Transparency

Every LLM call MUST be traced and logged with: latency (ms), input token count, output token
count, estimated cost (USD), model identifier, client organization, and success/failure status.
Cost per query MUST be attributable to the specific client organization that incurred it. Every
deployment MUST expose a `/health` endpoint. Application errors MUST be logged with sufficient
context (stack trace, request id, tenant id) to reproduce and diagnose the issue.

**Rationale**: SME clients scrutinize AI operational costs closely. Inability to report
per-client spend is a commercial disqualifier. Observability also enables early detection of
runaway usage before it becomes a financial or reputational incident for the consultancy.

### VIII. Test-Driven Quality

No module MAY be considered complete without unit tests achieving ≥ 80% line coverage for
core modules. Every module MUST also have at least one integration test executed against real
external dependencies (live PostgreSQL instance, actual LLM API call — no mocks for integration
tests). All public functions and classes MUST have docstrings. Type hints are MANDATORY
throughout the entire codebase, including test files.

**Rationale**: A solo operator cannot afford regressions discovered in production across
multiple client deployments. Tests are the primary safety net for a codebase deployed
simultaneously in multiple live environments.

## Technology Stack

The following stack is NON-NEGOTIABLE. Deviations require a formal ADR (see Development
Philosophy) and a governance amendment to this constitution before any implementation begins.

| Layer | Mandated Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | Minimum version; 3.12+ preferred for new modules |
| API Framework | FastAPI | |
| Database | PostgreSQL | Primary relational store; multi-tenant schema required |
| Vector Search | pgvector | Initial choice; MUST be swappable via provider interface |
| LLM Providers | OpenAI, AWS Bedrock | Primary; Anthropic supported; provider interface required |
| Infrastructure | Docker | All deployments MUST be containerised |
| Cloud | AWS (EC2 or ECS) | Target deployment environment |
| CI/CD | GitHub Actions | |
| Frontend | Minimal React or plain HTML | Only what each pilot strictly requires; no gold-plating |

Credentials and secrets MUST be managed via environment variables in local development and
AWS Secrets Manager in all cloud deployments. No credential MAY appear in version control,
Dockerfiles, or build artefacts.

## Development Philosophy & Definition of Done

### Build-to-Use, Never Speculative

Every feature added to the framework MUST be justified by a real, active use case from one
of the current pilot clients (bicycle workshop, tourist shop, topography firm). Features
without a demonstrable pilot requirement MUST NOT be merged into the framework, regardless
of how universally reusable they appear in the abstract.

### MVP Before Extension

The MVP for any feature MUST be deployable and demonstrable before any additional capability
is layered on top. Incremental delivery is the only permitted delivery model. No half-finished
implementations may be merged.

### Document Decisions, Not Just Code

Every significant architectural choice MUST be recorded as an Architecture Decision Record
(ADR) stored in `docs/adr/`. ADRs MUST include: context, decision made, rationale, and
known consequences. Code comments MAY reference an ADR by ID but MUST NOT substitute for it.

### Module Definition of Done

A module is complete when ALL of the following conditions are satisfied:

1. Unit tests pass with ≥ 80% line coverage.
2. At least one integration test executes successfully against real dependencies
   (live PostgreSQL, actual LLM API call).
3. A `README.md` exists in the module directory covering: purpose, inputs/outputs,
   configuration reference (all env vars), and at least one usage example.
4. All configuration is driven by environment variables — zero hardcoded values.
5. The module has been exercised in at least one end-to-end scenario with a real or
   simulated client dataset.

## Governance

This constitution supersedes all other practices, guidelines, and informal conventions for
the KnowledgeAI framework. When any practice conflicts with a principle stated here, this
constitution takes precedence.

**Amendments**: Any amendment MUST (a) increment the version line according to the semantic
versioning policy below, (b) update the Sync Impact Report comment at the top of this file,
and (c) be reflected in all dependent templates before the amendment is considered complete.

**Versioning policy**:
- **MAJOR**: Removal or backward-incompatible redefinition of an existing principle.
- **MINOR**: New principle or section added; material expansion of existing guidance.
- **PATCH**: Clarification, wording fix, or non-semantic refinement.

**Compliance**: Every feature implementation MUST pass the Constitution Check in
`plan-template.md` before Phase 0 research begins, and MUST be re-checked after Phase 1
design. Any violation MUST be documented in the Complexity Tracking table with explicit
justification; undocumented violations are grounds for rejecting a merge.

**Version**: 1.0.0 | **Ratified**: 2026-07-04 | **Last Amended**: 2026-07-04