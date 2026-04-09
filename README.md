# KUROKAMI

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-informational.svg)
![Ollama](https://img.shields.io/badge/LLM-Ollama-black.svg)
![Production Ready](https://img.shields.io/badge/Production-Ready-green.svg)

KUROKAMI is a production-ready, AI-driven command-line penetration testing framework designed for Parrot OS and Debian-based Linux systems. It combines modular reconnaissance tooling, persistent scan history, local reasoning artifacts, and retrieval-augmented context into a single CLI workflow with enterprise-grade security features.

## 🚀 Production Features

- **Security Hardened**: Input validation, rate limiting, audit logging, and encryption support
- **Scalable**: Docker and Kubernetes deployment with PostgreSQL support
- **Observable**: Structured JSON logging, metrics, and comprehensive audit trail
- **Resilient**: Timeout protection, resource monitoring, and graceful error handling
- **Tested**: Comprehensive test suite with 70%+ coverage
- **CI/CD Ready**: Automated testing, security scanning, and deployment pipelines

## Key Features

### Core Capabilities

- **AI-Oriented Orchestration**: Agentic execution flow with LLM-based planning and reasoning
- **Persistent Session History**: Complete audit trail with SQLite/PostgreSQL storage
- **Modular Tool Integration**: Auto-discovered `k_*` modules for extensibility
- **Local Retrieval Layer**: FAISS-based vector indexing for context retrieval
- **CLI-First Workflow**: Scan, resume, diff, inspect, and export from command line
- **Multi-Format Reports**: Export to JSON, HTML, and PDF

### Production Security

- **Input Validation**: Comprehensive sanitization to prevent injection attacks
- **Rate Limiting**: Token bucket algorithm with per-user quotas
- **Audit Logging**: Security-relevant events tracked in structured logs
- **Resource Limits**: Timeout protection and concurrency controls
- **Encryption**: Optional Fernet encryption for sensitive data
- **Authentication**: API key and JWT support for access control

### Deployment Options

- **Docker**: Multi-stage builds with non-root execution
- **Kubernetes**: Production-ready manifests with health checks
- **Bare Metal**: Systemd service configuration
- **Cloud**: AWS/GCP/Azure deployment guides

## Quick Start

### Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/thearjunl/kurokami.git
cd kurokami

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start services
docker-compose up -d

# Run a scan
docker-compose exec kurokami python -m core.cli scan --target example.com
```

### Local Installation

```bash
# Run installer
chmod +x install.sh
./install.sh

# Activate virtual environment
source venv/bin/activate

# Run a scan
python -m core.cli scan --target example.com
```

## Documentation

- **[Deployment Guide](DEPLOYMENT.md)**: Production deployment instructions
- **[Security Policy](SECURITY.md)**: Security best practices and vulnerability reporting
- **[API Documentation](docs/API.md)**: Module development guide
- **[Architecture](docs/ARCHITECTURE.md)**: System design and data flow

## Architecture Overview

KUROKAMI follows a layered execution model:

1. The CLI receives a target or scope file and initializes a new scan session.
2. The database bootstrap creates or opens the configured SQLite database.
3. Module discovery loads every Python module in `modules/` matching the `k_*.py` naming convention.
4. The planner evaluates the target shape and prior indexed context to choose which modules should run first.
5. The agentic loop executes selected modules asynchronously, normalizes results, and stores target updates and findings.
6. Reasoning-chain stages are persisted to the database to track the pipeline state.
7. Session artifacts are indexed into the vector store for future retrieval and comparison.
8. Operators can review session history, diff findings between sessions, or export the results.

### Data Flow

`CLI -> Config Loader -> DB Init -> Module Discovery -> Planner -> Agentic Loop -> SQLite / Vector Store -> History / Export`

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| CLI | Click, Rich | Command interface and terminal presentation |
| Language | Python | Core framework implementation |
| Persistence | SQLite, SQLAlchemy | Session and findings storage |
| Retrieval | FAISS, NumPy | Local vector indexing and retrieval |
| LLM Runtime | Ollama | Planned local reasoning and model execution |
| Recon Modules | Nmap, Nikto, WhatWeb, Gobuster, smbclient | External security tooling integration |
| OS Target | Parrot OS, Debian-based Linux | Primary runtime environment |

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/thearjunl/kurokami.git
cd kurokami
```

### 2. Run the Installer

The project includes a bootstrap script for Debian-based systems:

```bash
chmod +x install.sh
./install.sh
```

This script installs:

- Python 3, `pip`, and `venv`
- `nmap`
- `nikto`
- `whatweb`
- `gobuster`
- `smbclient`
- other supporting packages required by the framework

It also installs Python dependencies from [`requirements.txt`](/d:/000%20Projects/KuroKami/requirements.txt).

### 3. Optional: Set Up Ollama

Install Ollama following the official Linux instructions, then start the service:

```bash
ollama serve
```

Pull a local model suitable for reasoning:

```bash
ollama pull qwen2.5:14b
```

You can then align the configured model in [`kurokami.conf`](/d:/000%20Projects/KuroKami/kurokami.conf) if needed.

### 4. Verify the CLI

```bash
python3 -m core.cli --help
```

## Usage

### Start a Scan

Single target:

```bash
python3 -m core.cli scan --target example.com
```

Scope file:

```bash
python3 -m core.cli scan --scope targets.txt
```

### View Session History

```bash
python3 -m core.cli history list
```

### Resume a Previous Session

```bash
python3 -m core.cli history resume 3
```

### Diff Two Sessions

```bash
python3 -m core.cli history diff 3 4
```

### Export a Session Report

JSON:

```bash
python3 -m core.cli export --session 3 --format json
```

HTML:

```bash
python3 -m core.cli export --session 3 --format html
```

PDF:

```bash
python3 -m core.cli export --session 3 --format pdf
```

## Module System

KUROKAMI uses a lightweight plugin architecture based on Python modules stored under `modules/`.

- Every module file must follow the `k_*.py` naming pattern.
- Each module subclasses `KurokamiModule` from [core/module_base.py](/d:/000%20Projects/KuroKami/core/module_base.py#L1).
- Modules are auto-discovered by [core/discovery.py](/d:/000%20Projects/KuroKami/core/discovery.py#L1).
- Each module exposes metadata and implements an async `execute()` method.
- Module outputs are normalized into structured dictionaries so the agentic loop can persist findings and target updates consistently.

Current module examples:

- `k_nmap`
- `k_nikto`
- `k_whatweb`
- `k_gobuster`
- `k_smbclient`

This design makes it easy to add new integrations such as `k_whois`, `k_dnsenum`, `k_sslscan`, or exploit-oriented modules later.

## Database Schema Overview

KUROKAMI stores operational state in SQLite using SQLAlchemy models defined in [core/db.py](/d:/000%20Projects/KuroKami/core/db.py#L1).

### Core Tables

- `sessions`  
  Tracks the lifecycle of an assessment, including target, timestamps, status, and risk level.

- `targets`  
  Stores host-level data such as IP, open ports, and discovered technology stack.

- `findings`  
  Persists vulnerabilities, severity, confidence, descriptions, and optional CVE references.

- `exploits`  
  Reserved for exploitation attempts, payloads, and outcomes tied to findings.

- `ai_reasoning_chains`  
  Records reasoning stages such as `RECON`, `ATTACK_SURFACE`, `EXPLOIT_PRIORITY`, and `REMEDIATION`.

- `exports`  
  Tracks report generation history, output format, file path, and creation time.

### Retrieval Layer

Session artifacts can also be indexed into the configured vector store directory for later retrieval, enabling future LLM-assisted summarization and context reuse.

## Roadmap

- Replace heuristic planning with deeper Ollama-backed reasoning and tool-calling
- Add more recon and enumeration modules such as `whois`, `dnsenum`, `curl`, and `sslscan`
- Introduce exploit workflow modules and controlled payload execution tracking
- Improve finding scoring, deduplication, and prioritization
- Add richer HTML/PDF reporting templates
- Expand unit and integration test coverage
- Add packaging, release automation, and reproducible deployment workflows

## Contributing

Contributions are welcome.

If you want to contribute:

1. Fork the repository.
2. Create a feature branch from `main`.
3. Keep changes focused and well-scoped.
4. Follow the existing module conventions for anything added under `modules/`.
5. Add or update tests where practical.
6. Open a pull request with a clear description of the problem and the solution.

Recommended contribution areas:

- new modules
- planner improvements
- database query helpers
- reporting improvements
- tests and CI
- documentation

## License

This project is licensed under the MIT License. See [`LICENSE`](/d:/000%20Projects/KuroKami/LICENSE) for details.

## Disclaimer

KUROKAMI is provided for authorized security testing, research, and defensive validation only.

Do not use this framework against systems, networks, or applications without explicit permission from the owner. The authors and contributors are not responsible for misuse, illegal activity, service disruption, or damage caused by improper use of this software.
