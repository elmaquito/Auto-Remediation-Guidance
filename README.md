# Nexthink v6 Auto-Remediation Guidance

Welcome! This template repository is designed for teams implementing auto-remediation with Nexthink v6 and PowerShell 5.1.

- 📄 Guidance docs
- 🖥️ PowerShell remediation scripts
- 🧪 Comprehensive testing framework
- 📝 Playbooks and best practices

---

## 📚 Contents

- `docs/` — Guidance and documentation on auto-remediation concepts and Nexthink v6 integration.
- `scripts/` — Example PowerShell 5.1 scripts for remediation scenarios.
- `tests/` — Comprehensive test suite using Pester framework.
- `playbooks/` — End-to-end remediation playbooks and workflows.

---

## 🚀 Getting Started

1. Review [docs/introduction.md](docs/introduction.md) for an overview.
2. Explore [scripts/](scripts/) for PowerShell remediation examples.
3. Set up testing with [docs/testing/README.md](docs/testing/README.md).
4. See [playbooks/](playbooks/) for practical, step-by-step responses.

### Quick Start with Testing

```powershell
# Install testing dependencies
.\Install-TestDependencies.ps1

# Run all tests
.\Run-Tests.ps1

# Run with coverage
.\Run-Tests.ps1 -Coverage

# Watch mode for development
.\Run-Tests.ps1 -Watch
```

---

## 🧪 Testing Framework

This repository includes a comprehensive testing framework:

- **Unit Tests**: Test individual functions and components
- **Integration Tests**: Test complete script execution  
- **Security Analysis**: Automated security vulnerability scanning
- **Code Coverage**: Track test coverage with detailed reports
- **CI/CD Integration**: GitHub Actions for automated testing

### Test Commands

```powershell
# Install dependencies
.\Install-TestDependencies.ps1

# Run unit tests only
.\Run-Tests.ps1 -TestType Unit

# Run integration tests only  
.\Run-Tests.ps1 -TestType Integration

# Run all tests with coverage
.\Run-Tests.ps1 -Coverage

# Advanced test runner
.\Test-Runner.ps1 -Coverage -CodeAnalysis
```

---

## 🤝 Contributing

- Open a pull request or issue for suggestions, questions, or improvements.
- See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

See [LICENSE](LICENSE) for licensing information.
