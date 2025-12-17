# Security Auditor MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Security policy enforcement and compliance auditing for AI systems.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

AI-powered security vulnerability scanning and remediation for codebases.

## Features

- **Codebase Scanning**: Detect security vulnerabilities in files and directories
- **Change Validation**: Verify proposed code changes don't introduce security issues
- **Patch Generation**: Automatically generate fixes for identified vulnerabilities
- **Severity Classification**: Issues categorized as critical/high/medium/low

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_codebase` | Scan a directory or file for security vulnerabilities |
| `validate_change` | Check if a proposed code change is safe |
| `generate_patch` | Generate a code patch to fix a specific vulnerability |

## Vulnerability Detection

Detects common security issues including:
- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Hardcoded credentials
- Insecure configurations

## Requirements

- Python 3.10+
- mcp SDK

## Installation

```bash
pip install mcp
```

## Usage

```bash
python server.py
```

## Integration

Works with Claude Code, Gemini CLI, and other MCP-compatible AI assistants to provide automated security auditing during development.

## License

MIT
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
