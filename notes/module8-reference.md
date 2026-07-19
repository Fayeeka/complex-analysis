# Module 8 Reference: Complex Analysis - Threat Intel & Multi-Source Correlation

## Claude Ecosystem Coverage

| Component | Feature | How We'll Use It |
|---|---|---|
| Slash Commands | /ingest-ti | Threat intel ingestion and TTP extraction |
| Plan Mode | Shift+Tab | Investigation scoping and planning |
| Subagents | .claude/agents/ | Parallel analysis of endpoint vs cloud logs |
| /model | Model selection | Opus for complex TTP extraction |
| Web Search | Threat intelligence | Research IOCs and threat actors |
| /context | Context monitoring | Track usage during large investigations |
| /compact | Context management | Preserve findings across long sessions |
| LiteLLM + Ollama | Multi-model verification | Cross-check analysis with local models |

## External Tools

| Tool | Purpose | Install |
|---|---|---|
| defuddle-cli | Extract clean content from threat intel URLs | npm install -g defuddle-cli |
| LiteLLM | Multi-model proxy | pip install 'litellm[proxy]' |
| Ollama | Local model runtime | curl -fsSL https://ollama.com/install.sh \| sh |

## Overview

Previous modules built tools for specific tasks — parsing logs,
validating rules, running queries. This module tackles two complex
analysis challenges:

1. **Threat Intelligence Processing**: Turn a threat report URL into
   actionable TTPs and a simulation plan
2. **Multi-Source Correlation**: Correlate events across endpoint
   (Windows) and cloud (Azure) logs

Both require Claude to reason through complex, unstructured inputs.

By the end:
- A /ingest-ti command that processes threat intel reports into ATT&CK
  mappings and simulation plans
- Experience correlating Windows and cloud logs
- Patterns for using Opus on complex reasoning tasks
- Techniques for plan mode, subagents, and context management
- Multi-model verification workflow using LiteLLM and local models

## The Problem

### Problem 1: Threat Intel Reports Are Unstructured

A threat intel team shares a blog post about a new campaign. Need to:
- Extract the TTPs described
- Map them to ATT&CK techniques
- Create a simulation plan for a purple team exercise

Manually reading and mapping is slow, difficult, and not repeatable.

### Problem 2: Multi-Source Correlation Is Hard

Investigating a potential compromise, with:
- Windows Security and Sysmon logs (endpoint)
- Azure AD sign-in and audit logs (cloud)

Each source tells part of the story. The challenge is correlating
across both to build a coherent timeline.

## 8.1 Setting Up the Project

New project setup, CLAUDE.md describes two workflows (threat intel
processing, multi-source investigation) and four log sources (Windows
Security, Sysmon, Azure AD sign-in, Azure AD audit).

Install defuddle-cli (npm install -g defuddle-cli) — extracts clean,
readable content from web pages (strips ads/nav/clutter), avoiding
token waste on raw HTML when processing threat intel blog posts.

## 8.2 Building the /ingest-ti Command

Takes a threat intel URL, produces: threat/campaign summary, ATT&CK
techniques identified, IOCs, recommended simulation plan.

Command structure (.claude/commands/ingest-ti.md):
- Argument: url (required)
- Step 1: defuddle "$url" --format markdown to extract clean content
- Step 2: Analyze for Threat Overview (actor, targets, timeframe), TTPs
  mapped to ATT&CK across all tactic categories (with technique ID, how
  it was used, confidence level), IOCs (IPs, domains, hashes, paths,
  registry keys, emails), and a Simulation Plan (applicable Atomic Red
  Team tests by technique ID, gaps noted, prioritized by confidence +
  test availability)
- Step 3: Output to analysis/ti-[date]-[campaign-name].md with
  frontmatter (source URL, extraction date)

Test: /ingest-ti <url> (restart session first to load the command).

**Enhancing with Opus:** for complex/nuanced reports, /model → select
Opus, then re-run /ingest-ti — may catch techniques Sonnet missed.

## 8.3 Plan Mode for Investigation Design

Before analyzing logs, use plan mode (Shift+Tab twice, or /plan) to
scope the investigation — Claude can read but not modify anything.

Example scoping prompt: list log files and time ranges, identify event
types present, identify correlation fields (timestamps, usernames,
IPs), propose a reasonable investigation approach.

Exit plan mode (Shift+Tab) once scoping is done, then execute.

## 8.4 Subagents for Parallel Analysis

Keep each log-source analysis focused, avoid filling main context.

**endpoint-analyst** (.claude/agents/endpoint-analyst.md, tools: Read,
Bash): analyzes Windows Security + Sysmon logs for authentication
events (4624/4672/4625), process execution (suspicious chains, LOLBins,
encoded PowerShell), persistence (registry, scheduled tasks, services),
lateral movement indicators, and out-of-place browser executions (odd
flags/command-line args). Output: Timeline, IOCs, ATT&CK Techniques,
Confidence, Questions.

**cloud-analyst** (.claude/agents/cloud-analyst.md, tools: Read, Bash):
analyzes Azure AD sign-in/audit logs for authentication anomalies
(unusual location/device, impossible travel, token replay, multi-OS/
user-agent users), privilege changes, resource access, and correlation
points (shared usernames/timestamps/IPs with endpoint). Output:
Timeline, IOCs, ATT&CK Techniques, Confidence, Correlation Hints.

Usage: spawn both in parallel ("Use the endpoint-analyst agent to
analyze logs/windows/. Use the cloud-analyst agent to analyze
logs/cloud/. Return both analyses so I can correlate them."), save
outputs to analysis/endpoint.md and analysis/cloud.md.

**Correlation step:** prompt Claude (ideally on Opus) to correlate both
analyses: timeline alignment, user correlation, IP correlation, likely
attack chain (initial access → endpoint actions → cloud pivot →
objective), confidence assessment, gaps.

Key caveat from the course: AI isn't a magic bullet for this — still
need real understanding of attacks/tradecraft/telemetry to craft proper
prompts and workflows; results are "underwhelming" without that.

## 8.5 Multi-Model Verification with LiteLLM

Route non-Claude models through LiteLLM (open-source proxy) since
Claude Code doesn't natively support them. Use case: second model
sanity-checks the first's analysis, catching blind spots/hallucinations
— especially valuable for security analysis.

Why multi-model: different training data = different blind spots; cost
optimization (cheap/local models for simple validation); air-gapped
environments (Ollama fully local); compliance (keep sensitive analysis
on-prem).

**Hardware note:** local models need significant compute; without a
GPU, expect 30-120+ second responses. Alternatives: cloud models
(GPT-4o), smaller local models (mistral, llama3.2:3b), or just accept
slower verification.

**Architecture:** Claude Code → LiteLLM Proxy (translates API formats)
→ Ollama (local) or OpenAI (cloud).

**Setup (3 terminals):**
1. Ollama server: `ollama serve` (port 11434)
2. Pull tool-calling-capable models: llama3.1, qwen2.5, mistral (NOT
   llama3/phi3/codellama — those don't support tools). Install LiteLLM
   (`pip install 'litellm[proxy]'`), configure litellm-config.yaml
   mapping model names to ollama_chat/<model> endpoints, start with
   `litellm --config litellm-config.yaml --port 8888`
3. Claude Code, routed via ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN env
   vars pointing at the LiteLLM proxy, using --model llama3.1

Verify via curl to /v1/models and /v1/messages before connecting Claude
Code.

**Verification subagent** (.claude/agents/verify-local.md, model:
llama3.1, tools: Read): reviews analysis for unsupported conclusions,
alternative explanations, logical gaps — outputs Agrees/Questions/
Disagrees per finding.

**Troubleshooting table:** "does not support tools" → wrong model
choice; "Invalid model name" → not in litellm config; connection
refused → Ollama/LiteLLM not running; very slow → normal for CPU-only.

## 8.6 Context Management

Complex analyses fill context fast — critical to manage proactively.

/context regularly during long investigations.

/compact with explicit preservation instructions when context hits
60-70% (e.g. preserve attack timeline, key IOCs, confirmed ATT&CK
techniques, specific correlations, outstanding questions).

Checkpoints: for long investigations, save explicit
analysis/checkpoint-phaseN.md files capturing current understanding,
confirmed findings with evidence, hypotheses/confidence, next steps.

## 8.7 Putting It Together

**Workflow 1 — Threat Intel Processing:** get URL → /ingest-ti <url> →
review TTPs/simulation plan → optionally switch to Opus and re-run for
complex reports → use output for purple team planning (Module 10).

**Workflow 2 — Multi-Source Investigation:** /init + CLAUDE.md → plan
mode to scope → create subagent definitions per source → run subagents
in parallel → switch to Opus → correlate findings → web search for
IOC/technique context → document findings → /compact with preservation
or checkpoint.

## Session Notes: LiteLLM Installation Blocked on Windows

Attempted the full section 8.5 setup (Ollama + LiteLLM + local model
verification). Ollama itself installed and worked cleanly:
- ollama serve running as a background service automatically
- llama3.1 pulled successfully (4.9GB)
- Confirmed via `ollama list` and a direct HTTP check to localhost:11434

LiteLLM installation (`pip install 'litellm[proxy]'`) hit a cascading
dependency chain on this Windows machine:
1. Required compiling a Rust extension (litellm-rust) — Rust/Cargo
   weren't installed, triggered an automatic install via the
   `puccinialin` installer
2. That installer's own PATH detection had a real bug — it installs
   Rust into an isolated cache directory, verifies cargo works there,
   then checks the *system* PATH and fails, even though it just used
   cargo successfully seconds earlier. Worked around by manually adding
   the toolchain's bin directory to PATH.
3. With Rust/Cargo now available, the actual compilation failed because
   it also requires Visual Studio Build Tools with the C++ workload
   (link.exe) — a separate, large (multi-GB) install not mentioned in
   the course material.

**Decision:** stopped here rather than installing VS Build Tools too.
This would have been a fourth layer of heavy infrastructure (following
the Node upgrade needed for defuddle earlier this module) just to reach
the point of running the actual LiteLLM proxy.

**Disk space note:** freeing space for this section also required
deleting an 8GB unused Ubuntu VM, since the drive was at ~90% capacity
before starting.

**Takeaway:** section 8.5's multi-model verification pattern is
conceptually sound and valuable (using a second model to sanity-check
Claude's analysis, catching blind spots), but the actual LiteLLM+Ollama
setup has a real, non-trivial Windows-specific barrier beyond what the
course documents — a full Rust + MSVC C++ build toolchain, not just a
pip install. Worth knowing this before committing to it on a
resource-constrained or Windows-based machine.

## Module 8 Wrap-Up Summary

**Workflow 1 — Threat Intel Processing:** Built and tested /ingest-ti
against a real Unit 42 report on Screening Serpens (Iran-nexus APT).
Produced 21 mapped ATT&CK techniques, 23 real IOCs, and an honest
Atomic Red Team gap analysis (verified against the live GitHub index
rather than fabricating test IDs for techniques with no existing
coverage).

**Workflow 2 — Multi-Source Investigation:** Built endpoint-analyst and
cloud-analyst subagents, ran them in parallel against synthetic
Windows/Sysmon + Azure AD logs modeling a real technique (session
cookie theft via Chrome DevTools Protocol, replayed as a pass-the-cookie
attack). Used plan mode to scope before analyzing, switched to Opus for
the final correlation step, and produced a full investigation trail
(endpoint.md, cloud.md, correlation.md) with honest confidence caveats
and prioritized collection gaps.

**Section 8.5 (LiteLLM/Ollama):** Ollama itself worked cleanly on
Windows. LiteLLM did not — blocked by a real, undocumented dependency
chain (Rust toolchain → MSVC C++ Build Tools) beyond what a simple pip
install suggests. Documented as a genuine environment limitation rather
than pushed through, given the module's remaining scope.

**Context management:** Checked /context after this entire session's
work (threat intel analysis, subagent correlation, extensive Node/Rust/
LiteLLM troubleshooting, VM cleanup) — still at only 14% usage, 82%
free. Demonstrates that focused subagents and disciplined workflows
keep even complex, multi-hour sessions well within budget without
needing to compact or clear.

**Real infrastructure work done this module beyond the course's own
scope:** upgraded Node 16→24 to fix defuddle, freed ~8GB disk space
(deleted an unused VM) to make room for local models, debugged a real
bug in Rust's Windows installer PATH detection, filed away a genuine
Windows-specific gap in the LiteLLM install path.

**Overall takeaway:** this module's course material assumes a
relatively clean, modern, likely Unix-like or well-provisioned
environment. Real-world execution on an older Windows setup surfaced
several genuine infrastructure gaps not present in the course's happy
path — consistent with the pattern from Module 7's hook investigation:
verify, don't assume, and treat course material as a guide rather than
a guarantee.
