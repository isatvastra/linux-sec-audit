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

## Requirements

### System
- Linux
- Python 3.9+
- Root privileges recommended for full results

### Python dependency
```bash
pip install requests
