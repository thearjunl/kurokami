<div align="center">

#  KUROKAMI

### AI-Driven Penetration Testing Framework

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Production](https://img.shields.io/badge/Production-Ready-success?style=for-the-badge)](PRODUCTION_READINESS.md)

**Enterprise-grade penetration testing framework with AI-powered orchestration, modular architecture, and comprehensive security features.**

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Architecture](#-architecture) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

KUROKAMI is a production-ready, AI-driven command-line penetration testing framework designed for security professionals. It combines intelligent reconnaissance, persistent session management, and retrieval-augmented analysis into a unified workflow with enterprise-grade security controls.

### Why KUROKAMI?

- 🤖 **AI-Powered**: LLM-based planning and reasoning with Ollama integration
- 🔒 **Security First**: Input validation, rate limiting, audit logging, and encryption
- 📊 **Session Management**: Complete audit trail with SQLite/PostgreSQL storage
- 🔌 **Modular Design**: Extensible plugin architecture for custom tools
- 🐳 **Cloud Native**: Docker and Kubernetes ready with health checks
- 📈 **Observable**: Structured logging, metrics, and monitoring endpoints
- 🧪 **Well Tested**: Comprehensive test suite with 70%+ coverage

---

## ✨ Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **AI Orchestration** | Intelligent module selection and execution planning using LLM reasoning |
| **Persistent History** | Complete session tracking with findings, exploits, and reasoning chains |
| **Modular Tools** | Auto-discovered `k_*` modules for reconnaissance and exploitation |
| **Vector Retrieval** | FAISS-based indexing for context-aware analysis |
| **Multi-Format Reports** | Export to JSON, HTML, and PDF with customizable templates |
| **Resume & Diff** | Resume interrupted scans and compare findings across sessions |

### Production Security

| Feature | Description |
|---------|-------------|
| **Input Validation** | Comprehensive sanitization preventing injection attacks |
| **Rate Limiting** | Token bucket algorithm with per-user quotas |
| **Audit Logging** | Security events tracked in structured JSON logs |
| **Resource Controls** | Timeout protection and concurrency limits |
| **Encryption** | Fernet encryption for sensitive data at rest |
| **Authentication** | API key and JWT support for access control |

### Deployment Options

<table>
<tr>
<td width="33%" align="center">

**🐳 Docker**

Multi-stage builds<br>
Non-root execution<br>
Health checks

</td>
<td width="33%" align="center">

**☸️ Kubernetes**

Production manifests<br>
Auto-scaling<br>
Service mesh ready

</td>
<td width="33%" align="center">

**🖥️ Bare Metal**

Systemd service<br>
Direct hardware<br>
Custom configs

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Docker Deployment (Recommended)

```bash
# Clone repository
git clone https://github.com/thearjunl/kurokami.git
cd kurokami

# Configure environment
cp .env.example .env
nano .env  # Edit with your settings

# Start all services (PostgreSQL, Ollama, KUROKAMI)
docker-compose up -d

# Verify deployment
docker-compose ps

# Run your first scan
docker-compose exec kurokami python -m core.cli scan --target example.com

# View results
docker-compose exec kurokami python -m core.cli history list
```

### Local Installation

```bash
# Install system dependencies and Python packages
chmod +x install.sh
./install.sh

# Activate virtual environment
source venv/bin/activate

# Configure Ollama (optional but recommended)
ollama serve &
ollama pull qwen2.5:14b

# Run a scan
python -m core.cli scan --target example.com
```

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| **[Deployment Guide](DEPLOYMENT.md)** | Production deployment for Docker, Kubernetes, and bare metal |
| **[Security Policy](SECURITY.md)** | Security best practices and vulnerability reporting |
| **[Production Readiness](PRODUCTION_READINESS.md)** | Implementation details and production checklist |
| **[Contributing Guide](#-contributing)** | How to contribute modules, tests, and improvements |

---

## 💻 Usage

### Interactive Mode

```bash
# Launch interactive shell
python -m core.cli

# Menu-driven interface
[1] New Scan
[2] View History
[3] Export Report
[4] Exit
```

### Command Line Interface

```bash
# Single target scan
python -m core.cli scan --target 192.168.1.1

# Scope file scan
python -m core.cli scan --scope targets.txt

# View session history
python -m core.cli history list

# Resume interrupted scan
python -m core.cli history resume 3

# Compare two sessions
python -m core.cli history diff 3 4

# Export reports
python -m core.cli export --session 3 --format json
python -m core.cli export --session 3 --format html
python -m core.cli export --session 3 --format pdf

# View configuration
python -m core.cli config
```

---

## 🏗️ Architecture

### System Design

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│                    (Click + Rich UI)                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Orchestration Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Planner    │  │ Agentic Loop │  │  Checkpoint  │     │
│  │  (AI/LLM)    │  │  (Executor)  │  │   Manager    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                     Module Layer                             │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │
│  │ k_nmap │ │k_nikto │ │k_gobust│ │k_whatwb│ │  ...   │  │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Persistence Layer                           │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  PostgreSQL/     │         │  FAISS Vector    │         │
│  │  SQLite          │         │  Store           │         │
│  │  (Sessions,      │         │  (RAG Context)   │         │
│  │   Findings)      │         │                  │         │
│  └──────────────────┘         └──────────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User Input → Validation → Rate Limit Check → Session Init
     ↓
Module Discovery → AI Planning → Module Execution
     ↓
Finding Normalization → Deduplication → Persistence
     ↓
Risk Calculation → Reasoning Chain → Vector Indexing
     ↓
Report Generation → Audit Logging → Export
```

---

## 🔧 Module System

KUROKAMI uses a plugin architecture for easy extensibility.

### Available Modules

| Module | Phase | Description |
|--------|-------|-------------|
| `k_nmap` | Recon | Port scanning and service detection |
| `k_nikto` | Recon | Web server vulnerability scanning |
| `k_whatweb` | Recon | Web technology fingerprinting |
| `k_gobuster` | Recon | Directory and file brute-forcing |
| `k_whois` | Recon | Domain registration information |
| `k_dnsenum` | Recon | DNS enumeration and zone transfers |
| `k_sslscan` | Recon | SSL/TLS configuration analysis |
| `k_smbclient` | Recon | SMB share enumeration |
| `k_curl` | Recon | HTTP header and response analysis |
| `k_http_trace_exploit` | Exploit | HTTP TRACE method exploitation |

### Creating Custom Modules

```python
from core.module_base import KurokamiModule

class MyCustomModule(KurokamiModule):
    @property
    def name(self) -> str:
        return "k_custom"
    
    @property
    def description(self) -> str:
        return "My custom security module"
    
    @property
    def tool_schema(self) -> dict:
        return {
            "name": "k_custom",
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }
        }
    
    async def execute(self, target: str, **kwargs) -> dict:
        # Your implementation here
        return {
            "status": "completed",
            "output": "Scan results",
            "findings": [],
            "target_updates": {}
        }
```

Place your module in `modules/k_custom.py` and it will be auto-discovered.

---

## 🗄️ Database Schema

### Core Tables

```sql
sessions          -- Scan session lifecycle and metadata
├── id            -- Primary key
├── target        -- Target host/network
├── start_time    -- Session start timestamp
├── end_time      -- Session completion timestamp
├── status        -- Current status (running, completed, etc.)
├── risk_level    -- Computed risk (critical, high, medium, low)
└── current_stage -- Execution stage (RECON, EXPLOIT, etc.)

targets           -- Target host information
├── id            -- Primary key
├── session_id    -- Foreign key to sessions
├── host          -- Hostname
├── ip            -- IP address
├── open_ports    -- JSON array of open ports
└── tech_stack    -- JSON array of detected technologies

findings          -- Discovered vulnerabilities
├── id            -- Primary key
├── session_id    -- Foreign key to sessions
├── target_id     -- Foreign key to targets
├── vuln_name     -- Vulnerability name
├── severity      -- Severity level (critical, high, medium, low)
├── confidence    -- Confidence score (0.0-1.0)
├── description   -- Detailed description
└── cve_id        -- CVE identifier (if applicable)

exploits          -- Exploitation attempts
├── id            -- Primary key
├── finding_id    -- Foreign key to findings
├── payload       -- Exploit payload used
├── result        -- Exploitation result
└── attempted_at  -- Timestamp of attempt

ai_reasoning_chains -- AI decision tracking
├── id            -- Primary key
├── session_id    -- Foreign key to sessions
├── stage         -- Reasoning stage (RECON, ATTACK_SURFACE, etc.)
├── input_context -- Input data for reasoning
├── output        -- AI reasoning output
├── model_used    -- LLM model identifier
└── timestamp     -- Reasoning timestamp
```

---

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=core --cov=modules --cov-report=html

# Run specific test file
pytest tests/test_validators.py

# Run with verbose output
pytest -v

# Run only security tests
pytest -k "security or validation"
```

### Test Coverage

- ✅ Input validation (30+ tests)
- ✅ Rate limiting (10+ tests)
- ✅ Logging and audit trail (8+ tests)
- ✅ Configuration management
- ✅ Health checks
- ✅ Module integration

---

## 🔒 Security

### Security Features

- **Input Validation**: All user inputs sanitized to prevent injection attacks
- **Rate Limiting**: Configurable per-user request quotas
- **Audit Logging**: Complete trail of security-relevant events
- **Encryption**: Fernet encryption for sensitive data
- **Timeout Protection**: Prevents resource exhaustion
- **Non-Root Execution**: Docker containers run as unprivileged user

### Reporting Vulnerabilities

Please report security vulnerabilities to: **arjunl2026@mca.ajce.in**

See [SECURITY.md](SECURITY.md) for our security policy and disclosure process.

---

## 🛠️ Tech Stack

| Category | Technologies |
|----------|-------------|
| **Language** | Python 3.10+ |
| **CLI** | Click, Rich |
| **Database** | SQLAlchemy, PostgreSQL, SQLite |
| **Migrations** | Alembic |
| **Vector Store** | FAISS, NumPy |
| **LLM** | Ollama (qwen2.5, dolphin-mistral) |
| **Testing** | pytest, pytest-asyncio, pytest-cov |
| **Containerization** | Docker, Docker Compose |
| **CI/CD** | GitHub Actions |
| **Security Tools** | nmap, nikto, whatweb, gobuster, sslscan, smbclient |

---

## 🗺️ Roadmap

### Version 0.2.0 (Q2 2026)
- [ ] Web UI dashboard
- [ ] Real-time scan progress via WebSocket
- [ ] Advanced ML-based RAG embeddings
- [ ] Multi-tenancy support
- [ ] Slack/Email notifications

### Version 0.3.0 (Q3 2026)
- [ ] Plugin marketplace
- [ ] Custom report templates
- [ ] Integration with SIEM systems
- [ ] Advanced exploit modules
- [ ] Automated remediation suggestions

### Version 1.0.0 (Q4 2026)
- [ ] Enterprise features
- [ ] Role-based access control (RBAC)
- [ ] Compliance reporting (PCI-DSS, HIPAA)
- [ ] API gateway
- [ ] Horizontal scaling support

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute

- 🐛 **Report Bugs**: Open an issue with detailed reproduction steps
- 💡 **Suggest Features**: Share your ideas for improvements
- 📝 **Improve Documentation**: Fix typos, add examples, clarify instructions
- 🔧 **Submit Code**: Create new modules, fix bugs, add tests
- 🧪 **Write Tests**: Improve test coverage
- 🎨 **Design**: Improve UI/UX for CLI and reports

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/kurokami.git
cd kurokami

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install black isort flake8 mypy bandit

# Run tests
pytest

# Format code
black core modules tests
isort core modules tests

# Lint code
flake8 core modules tests
mypy core modules
```

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Format code (`black`, `isort`)
7. Commit changes (`git commit -m 'Add amazing feature'`)
8. Push to branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**KUROKAMI is provided for authorized security testing, research, and defensive validation only.**

- ✅ Use only on systems you own or have explicit permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Follow responsible disclosure practices
- ❌ Do not use for unauthorized access or malicious purposes
- ❌ Do not use against production systems without approval

**The authors and contributors are not responsible for misuse, illegal activity, service disruption, or damage caused by improper use of this software.**

---

## 🙏 Acknowledgments

- **Ollama Team** - For the excellent local LLM runtime
- **Security Community** - For the amazing open-source tools
- **Contributors** - For making this project better

---



<div align="center">

**Made with ❤️ by security professionals, for security professionals**

⭐ Star us on GitHub if you find this project useful!

[Report Bug](https://github.com/thearjunl/kurokami/issues) • [Request Feature](https://github.com/thearjunl/kurokami/issues) • [Documentation](DEPLOYMENT.md)

</div>
