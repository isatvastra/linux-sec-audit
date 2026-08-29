# Linux Security Auditor (Experimental)

An experimental, AI-assisted Linux security auditing tool written in Python.

This project is intended for **learning, research, and local system inspection**.  
It is not production-ready and must not be treated as a full security solution.

---

## Overview

This script performs a basic security assessment of a Linux system by checking:

- Sensitive file permissions and ownership
- SUID / SGID binaries
- SSH configuration weaknesses
- Firewall presence (nftables)
- Authentication and security logs
- Optional AI-assisted analysis using a local LLM (Ollama)

The goal is to combine traditional system inspection with lightweight AI reasoning to help explain risks and suggest remediation steps.


Screenshots / Example output:

![Audit results screenshot](https://raw.githubusercontent.com/isatvastra/linux-sec-audit/main/file_000000001cac820abe63ff915f6ee8a5.png)

_Figure: Example report output showing audited checks and findings._

![Device photo or additional output](https://github.com/isatvastra/linux-sec-audit/blob/main/file_000000001cac820abe63ff915f6ee8a5.png)

_Figure: Additional image related to the project._

---

## Features

- Permission and ownership auditing for critical system files
- Detection of unsafe SUID / SGID binaries
- SSH hardening checks
- Firewall detection
- Log inspection for suspicious activity
- Optional AI-based:
  - Risk explanations
  - Attack vector analysis
  - Risk scoring
  - Hardening script generation
- JSON or text-based reporting

---
## How It Works

The audit runs a series of Linux security checks, aggregates the findings,
and optionally uses a local Ollama LLM for additional risk analysis and
hardening recommendations.

![Linux Security Auditor Workflow](https://raw.githubusercontent.com/isatvastra/linux-sec-audit/main/linux_security_auditor_workflow_corrected-1.png)

## Requirements

### System
- Linux
- Python 3.9+
- Root privileges recommended for full results

### Python dependency
```bash
pip install requests
```
