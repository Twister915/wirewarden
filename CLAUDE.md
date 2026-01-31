# wirewarden

WireGuard configuration management for a family VPN. A monorepo with a Rust backend (API server + system daemon) and a React/Vite frontend for administration.

## Tech Stack

- **Framework:** Actix Web (API), Tokio (async runtime), SQLx (PostgreSQL)
- **Auth:** argon2 password hashing, JWT tokens
- **Frontend:** React + Vite + TypeScript
- **Target platforms:** Linux (daemon/server), any (API + frontend)
- **Patterns:** Workspace monorepo, shared types crate, systemd daemon

### Crate Structure

- `wirewarden-types` — shared API type definitions (lib)
- `wirewarden-api` — REST API server with auth, SQLx/PostgreSQL (bin)
- `wirewarden-daemon` — systemd daemon that pulls configs and manages WireGuard interfaces (bin)
- `frontend/` — React/Vite admin UI

## Build & Run

```bash
# API server
cargo run -p wirewarden-api

# Daemon
cargo run -p wirewarden-daemon -- --help

# Frontend
cd frontend && npm run dev

# Tests
cargo test --all-features

# Production build
cargo build --profile distribute
```

## Coding Standards

This project follows Joey's Rust style guide in `.claude/rust-style.md`.

Key principles:
- Nightly Rust, minimal dependencies, longevity over convenience
- Static dispatch, iterators over collect, lifetimes over cloning
- `thiserror` for errors, `tracing` for logs, `test-case` for tests
- `where` clauses over inline bounds, `impl Trait` when possible
- Derive `Debug` on all types, use table-based tests
- Block format for dependencies with features

## Database Architecture (wirewarden-api)

- Database code lives in `crates/wirewarden-api/src/db/` as a package.
- Organized into feature modules (`user`, `vpn`, `webauthn`).
- Each module defines model structs (`sqlx::FromRow`) and a store struct
  (`UserStore`, `VpnStore`, `ChallengeStore`) with async methods for data access.
