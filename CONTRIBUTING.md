# Contributing

Thanks for your interest in contributing to passport-client-certificate-auth.

## Development Setup

```bash
git clone https://github.com/tgies/passport-client-certificate-auth.git
cd passport-client-certificate-auth
npm install
```

## Running Checks

```bash
# Full test suite (unit + integration + e2e-style tests in this repo)
npm test

# Coverage run (must maintain 100% branches/functions/lines/statements)
npm run test:coverage

# Mutation tests (Stryker)
npm run test:mutation

# Full check (lint + typecheck + coverage)
npm run check
```

## Code Style

- Pre-commit hooks run linting automatically
- TypeScript strict mode is enabled
- Public API and user-visible behavior changes should be reflected in `index.d.ts` and README examples

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure `npm run check` passes and coverage remains 100%
5. Use conventional commits (for example: `feat:`, `fix:`, `docs:`)
6. Open a pull request with a clear test summary

## Adding Features

- Add or update tests for behavioral changes
- Update `README.md` for user-facing changes
- Update declarations in `index.d.ts` for API/type changes
- Add release notes under `## [Unreleased]` in `CHANGELOG.md`

## Reporting Bugs

Open an issue with:

- Node.js version
- Minimal reproduction
- Expected behavior vs actual behavior

## Security Issues

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.
