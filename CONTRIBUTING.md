# Contributing to IronWall

Thank you for your interest in making IronWall better! This document explains how to contribute.

## Code of Conduct

Be respectful, constructive, and professional in all interactions.

## How to Contribute

### Reporting Bugs
Open an issue with:
- IronWall version and OS
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (`docker logs ironwall-mgt`)

### Proposing Features
Open a Discussion before implementing large features. For small improvements, a PR is fine directly.

### Security Vulnerabilities
**Do NOT open a public issue.** Email contact@optimiumnexus.com with details. We aim to respond within 48 hours.

## Development Setup

```bash
git clone https://github.com/optimiumnexusllc/IronWall.git
cd IronWall
cp .env.example .env
# Edit .env with your test passwords
docker compose up -d postgres fvm
```

### Go Services
```bash
cd management/webserver
go mod download
go run main.go

# Run tests
go test ./... -v
```

### Premium Modules
```bash
cd premium/threat-intel
go mod download
go run main.go
```

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add GeoIP blocking support
fix: correct Redis connection retry logic
docs: update Helm chart README
chore: bump Go version to 1.22
refactor: simplify alerting dispatch
test: add unit tests for threat intel parser
```

## Pull Request Process

1. Fork and create a feature branch from `develop`
2. Write or update tests for your changes
3. Run `golangci-lint run` and fix any issues
4. Update relevant documentation
5. Submit PR against `develop` branch
6. At least 1 maintainer approval required before merge

## Branch Strategy

- `main` — stable releases only
- `develop` — integration branch for features
- `feature/*` — individual feature branches
- `hotfix/*` — urgent fixes for production

## License

By contributing, you agree that your contributions will be licensed under the GPL-3.0 license.
