# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-02-09

### Added

- Initial release of `passport-client-certificate-auth`
- Passport strategy wrapper around `client-certificate-auth` with reverse proxy support
- Support for AWS ALB, Cloudflare, Envoy, and Traefik certificate headers
- TypeScript declarations with full type coverage
- 100% test coverage with Jest (94 tests) and Stryker mutation testing
- Audit hooks (`onAuthenticated`, `onRejected`) for fire-and-forget logging
- Drop-in replacement for abandoned `passport-client-cert` package
- Comprehensive documentation with migration guide and security best practices
