---
id: aigw-mcp-descriptor-pinning
title: MCP tool descriptor pinning (rug-pull and new-tool detection) with the AI Gateway webhook guardrail (hybrid)
area: aigw
type: workaround            # guide | behavior | capability | limitation | workaround | position
status: verified          # verified | reported | stale | superseded | retracted
visibility: public        # internal | public
verified: 2026-10-17      # YYYY-MM-DD: date of the newest private evidence folder; empty if never tested
versions:                 # component: version, as confirmed by that evidence
  aigw-image: 2.29.0 (hybrid, chart airs-gw-1.2.0, unified mode; live run 2026-10-16)
  webhook: k8s/webhook.sh on python:3.12-slim, and a local run against the probe MCP server (2026-10-16)
  airs: Prisma AIRS sync scan API (v1/scan/sync/request), airs-cli 7.2.0 (2026-10-17)
source:                   # required when status is reported: where the claim came from
related: [aigw-byo-guardrail, aigw-byo-guardrail-mcp, aigw-mcp-airs-webhook]  # other article IDs
supersedes: []
superseded_by:
tags: [guardrail, webhook, byo-guardrail, mcp, mcp-gateway, hybrid, tool-poisoning, rug-pull, descriptor-pinning, tool-allowlist, airs, schema-validation]
---
Metadata for this article, read by `kb`, Obsidian Dataview and agents. The content is in [README.md](README.md).
