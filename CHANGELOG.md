# Changelog

All notable changes to Authz-ExeC are documented here.

## [1.0.0] — 2026-07-12

First public release.

### Core
- Cross-identity / cross-tenant access-control matrix (BAC · IDOR · BOLA · privilege escalation).
- Three-state detection model (privileged A / identity B / unauthenticated C) with a public-endpoint
  false-positive guard.
- Body normalisation (timestamps, UUIDs, CSRF/nonce, trace-ids), JSON key-set + token similarity,
  length tolerance, and per-verdict confidence scoring.
- Canary-marker cross-tenant leak detection.
- Guards for WAF / rate-limit, soft errors, empty results, and login redirects.

### Coverage
- **GraphQL:** auto-test POST queries; mutations gated behind an enabled write method.
- **API mode:** test JSON, files/images, XML, and empty/`204`/header-based responses; skip only HTML.
- **Value-aware de-dup:** same path with different parameter values / GraphQL queries each tested;
  identical requests never re-sent (persisted per project).
- **Skip identities' own traffic:** requests carrying a configured identity's session are ignored.
- **Test ALL methods except OPTIONS/HEAD** (default on) — includes PUT/PATCH/DELETE and mutations.

### UX
- Import Proxy History (in scope) and LIVE capture; colour pill verdicts; clickable count-chip filters;
  time column; free-text filter; request/response viewer; CSV export.
- JWT decoder with `alg:none` / strip-signature helpers; per-identity session check.
- Save/Load presets (identities + config) to a `.properties` file.

### Safety / hardening
- Scope-restricted on every send path (including the context menu and the unauthenticated baseline).
- Rate-limited bounded executor; own replays never loop (ToolType allowlist).
- Volatility double-send skips state-changing verbs; locale-safe (`Locale.ROOT`) case folding;
  include-regex fails open. Verified by an adversarial code review.

### Build / tests
- Zero external dependencies — compiles against Burp's bundled Montoya API, targets Java 17.
- Standalone self-tests for detector math, JWT, GraphQL/dedup, preset round-trip, and offscreen UI.
