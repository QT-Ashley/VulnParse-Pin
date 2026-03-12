# VulnParse-Pin Overview

VulnParse-Pin is a vulnerability intelligence and decision support engine for teams that need consistent, explainable risk prioritization from scanner output.

It ingests vulnerability reports (currently Nessus XML and OpenVAS XML), normalizes findings into a common model, enriches them with threat intelligence, computes risk scores, and ranks what to fix first.

## What it is

- A CLI-first vulnerability parsing and prioritization platform
- A deterministic pipeline: parse → enrich → score → rank → export
- A transparent scoring system with configurable weighting and risk bands
- A high-volume capable engine optimized for large finding sets

## What problem it solves

Security teams often face:

- Inconsistent scanner formats and schemas
- Manual triage bottlenecks and alert fatigue
- Fragmented enrichment from KEV, EPSS, NVD, and exploit sources
- Opaque risk calculations that are hard to audit or explain

VulnParse-Pin addresses this by standardizing data, centralizing enrichment, and producing reproducible risk outputs with clear provenance.

## Who it is for

- SOC analysts and vulnerability management teams
- Pentest and advisory organizations delivering client triage
- Security engineering teams building CI/CD security workflows
- Researchers and contributors needing auditable risk logic

## Core capabilities

- Schema detection and parser selection for supported scanner formats
- Enrichment from KEV, EPSS, NVD, and Exploit-DB (online/offline modes)
- Derived pass system for scoring and Top-N triage
- JSON and CSV export paths with secure defaults
- Presentation overlays for reporting consumers

## Why organizations use it

- **Faster triage:** converts raw findings into ranked remediation queues
- **Better governance:** explainable, configurable scoring policy
- **Operational fit:** scalable behavior from small scans to high-volume workloads
- **Security posture:** hardened I/O and sanitization controls in default flows

## Getting started

Read [Getting Started In 5 Minutes](Getting%20Started%20In%205%20Minutes.md) for a working first run.

Then continue with:

- [Architecture](Architecture.md)
- [Detection and Parsing](Detection%20and%20Parsing.md)
- [Pipeline System](Pipeline%20System.md)
- [Configs](Configs.md)

## Licensing overview

VulnParse-Pin is available under AGPLv3+ for free/open usage.

Commercial pathways (Enterprise and MSSP) are documented in [Licensing](Licensing.md), including template sections for organizations that need proprietary embedding or managed-service terms.

## Support VulnParse-Pin

- Contribute code and tests
- Propose new passes and parser improvements
- Report reproducible bugs and edge cases
- Sponsor development for roadmap acceleration

For project intent and strategic direction, see [Mission Statement](Mission%20Statement.md) and [Why VulnParse-Pin Exists](Why%20VulnParse-Pin%20Exists.md).
