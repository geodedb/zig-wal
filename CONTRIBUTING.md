# Contributing to wal

Thank you for your interest in contributing to wal! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment:

```bash
make pre-commit-install
make dev
```

> **Note on `zig-pkg/`:** Zig extracts fetched dependencies (including a vendored
> `protoc` binary) into the git-ignored `zig-pkg/` cache, sometimes with
> world-writable (`0777`) permissions. Treat it as a local build cache only — do
> not place it on a shared or multi-user filesystem, and never execute binaries
> from it on an untrusted host (SEC-0052).

## Reporting Bugs

Before submitting a bug report:

1. Check existing issues to avoid duplicates
2. Use the bug report template when creating a new issue
3. Include:
   - Zig version (`zig version`)
   - Operating system and version
   - Steps to reproduce
   - Expected vs actual behavior
   - Minimal reproduction code if possible

## Security Vulnerabilities

**Do not report security vulnerabilities through public issues.**

See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.

## Feature Requests

1. Check existing issues for similar requests
2. Use the feature request template
3. Describe the use case and expected behavior
4. Consider implementation complexity

## Submitting Changes

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding/updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Maintenance tasks

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear, atomic commits
3. Ensure all tests pass: `make ci`
4. Update documentation if needed
5. Submit a merge request with:
   - Clear description of changes
   - Reference to related issues
   - Test coverage for new code

### Code Style

- Follow Zig standard library conventions
- Use `zig fmt` for formatting (enforced by pre-commit)
- Write descriptive variable and function names
- Add doc comments for public APIs
- Keep functions focused and small

### Testing Requirements

- All new features must have tests
- Maintain or improve test coverage
- Tests must pass on all optimization levels:

```bash
make test-all-optimizations
```

## Code Review

All submissions require review. We aim to:

- Respond to PRs within 48 hours
- Provide constructive feedback
- Merge approved changes promptly

## Development Workflow

```bash
# Quick iteration loop
make dev

# Full validation before pushing
make ci

# Run specific test levels
make test-unit
make test-integration
```

## Questions?

- Open a discussion issue
- See [SUPPORT.md](SUPPORT.md) for support options

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
