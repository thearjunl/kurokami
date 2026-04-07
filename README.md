# KUROKAMI

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-informational.svg)
![Ollama](https://img.shields.io/badge/LLM-Ollama-black.svg)

KUROKAMI is an AI-driven command-line penetration testing framework designed for Parrot OS and Debian-based Linux systems. It combines modular reconnaissance tooling, persistent scan history, local reasoning artifacts, and retrieval-augmented context into a single CLI workflow. The goal is to provide a structured offensive security workspace that can discover targets, execute modules, preserve state, and support later analysis without scattering data across ad hoc scripts and terminal logs.

At its core, KUROKAMI is built around an agentic pipeline. A scan session begins from the CLI, initializes a database-backed session, discovers available `k_*.py` modules, executes the selected tools, records findings and reasoning-chain stages, and indexes session knowledge for later retrieval. This makes the framework useful not only for one-off execution, but also for tracking assessments over time, resuming work, comparing sessions, and exporting reports in multiple formats.

The project is intentionally local-first. SQLite is used for persistence, FAISS-compatible indexing is used for retrieval, and the framework is structured to integrate with local LLM runtimes such as Ollama for future planning and reasoning expansion. KUROKAMI is aimed at practitioners who want an extensible offensive security CLI with a transparent plugin model rather than a closed scanning appliance.

## Key Features

- AI-oriented scan orchestration  
  KUROKAMI uses an agentic execution flow that tracks reasoning stages, module decisions, and outputs throughout a session.

- Persistent session history  
  Every scan stores sessions, targets, findings, exploits, exports, and reasoning chains in SQLite for later inspection.

- Modular tool integration  
  Recon and enumeration capabilities are implemented as standalone `k_*` modules that are auto-discovered at runtime.

- Local retrieval layer  
  Session artifacts can be indexed into a FAISS-compatible vector store for later context retrieval and future LLM-assisted analysis.

- CLI-first workflow  
  Scan, resume, diff, inspect, and export workflows are accessible from a single Click-based command-line interface.

- Exportable reports  
  Sessions can be exported in `json`, `html`, and `pdf` formats for archival or downstream reporting workflows.

- Debian / Parrot OS alignment  
  The installer and module assumptions are oriented around common offensive tooling available on Debian-based security distributions.

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
