# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

This project builds repeatable workflows for complex security analysis tasks. There are two core workflows:

1. **Threat intel processing** — ingest threat intel reports, extract TTPs (tactics, techniques, procedures), and create simulation plans from them.
2. **Multi-source investigation** — correlate endpoint and cloud logs to investigate activity across sources.

## Log sources

Analysis and correlation work draws on:
- Windows Security events
- Sysmon events
- Azure AD sign-in logs
- Azure AD audit logs

## Status

No source files, build configuration, or code exist yet — this repository currently holds only planning/scope documentation.

When code is added to this project, update this file with:
- Build, lint, and test commands (including how to run a single test)
- The high-level architecture and structure of the codebase
