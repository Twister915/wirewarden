# Joey's Rust Style Guide

You are working on a Rust project that follows Joey's engineering philosophy. This guide teaches you how to write Rust code the way Joey wants it.

## Core Philosophy

**Always use nightly Rust.** All projects build against nightly. This gives access to the latest features and optimizations.

**Longevity over convenience.** Code should work in 5-10 years without modification. This means:
- Minimize dependencies (each one is a liability over time)
- Prefer pure Rust dependencies over native/FFI bindings
- Avoid experimental language features unless they solve something cleanly (nightly is fine, unstable features need justification)

**Performance is non-negotiable.** Prefer static dispatch, stack allocation, and iterator chains. Avoid premature abstraction.

**Reuse over rewrite.** Before writing new code, search the codebase for existing patterns. Build shared abstractions when you see duplication.

---

## Decision Framework

When facing a trade-off, ask these questions in order:

1. **Will this still compile and run in 5 years?** Fewer dependencies = more durable.
2. **Is this the fastest reasonable approach?** Prefer zero-cost abstractions.
3. **Does similar code already exist here?** Reuse or generalize it.
4. **Am I certain this abstraction is needed?** Wait until you've seen the full picture.

---

## Dependencies

**Note:** Version numbers in these examples may be outdated. Always check crates.io for current stable versions before adding dependencies.

### Executables / Programs

**Always include:**
```toml
thiserror = "1"
tracing = "0.1"

[dependencies.tracing-subscriber]
version = "0.3"
features = ["env-filter", "json"]
```

**Usually include:**
```toml
[dependencies.serde]
version = "1"
features = ["derive"]

serde_json = "1"    # only when you actually need JSON
```

**For async programs (80% of the time):**
```toml
[dependencies.tokio]
version = "1"
features = ["rt-multi-thread", "macros", "net", "sync", "time", "fs", "io-util"]
# IMPORTANT: Pick specific features. Never use "full".

[dependencies.tokio-util]
version = "0.7"

[dependencies.tokio-stream]
version = "0.1"

[dependencies.futures]
version = "0.3"

[dependencies.pin-project]
version = "1"
# Use when building custom Stream/Future implementations
```

**For CLI programs with arguments:**
```toml
[dependencies.clap]
version = "4"
features = ["derive"]
```

**Dependency format:**

Simple version-only dependencies: one line
```toml
serde_json = "1"
```

Any configuration beyond version: use block format
```toml
[dependencies.tracing-subscriber]
version = "0.3"
features = ["env-filter", "json"]
```

Version pinning: Use major version only (e.g., `"1"` not `"1.0.123"`) unless pinning a specific minor is required.

---

## Performance Patterns

**Static dispatch over dynamic:**
```rust
// GOOD: Compiler can inline and optimize
fn process<T>(item: T)
where
    T: Processor,
{ ... }

// AVOID when possible: Creates optimization boundary
fn process(item: &dyn Processor) { ... }
```

**Iterators over collect:**
```rust
// GOOD: Lazy, no intermediate allocation
fn get_names(users: &[User]) -> impl Iterator<Item = &str> {
    users.iter().map(|u| u.name.as_str())
}

// AVOID: Allocates unnecessarily
fn get_names(users: &[User]) -> Vec<&str> {
    users.iter().map(|u| u.name.as_str()).collect()
}
```

**Stack over heap:**
```rust
// GOOD: Stack allocated, no heap
let buffer: [u8; 256] = [0; 256];

// AVOID when size is known: Heap allocation
let buffer: Vec<u8> = vec![0; 256];
```

**Lifetimes over cloning:**
```rust
// GOOD: Zero-copy reference
fn process_data(data: &str) -> &str { ... }

// AVOID as first resort: Hidden allocation cost
fn process_data(data: &str) -> String { data.to_string() }
```

**Avoid boxing futures and streams.** Use `impl Future` or `impl Stream` instead.

**Use lifetime elision whenever possible.** Only write explicit lifetimes when the compiler requires disambiguation.

**Use `where` clauses instead of inline bounds.**

**Prefer `impl Trait` when you don't need to name the type.**

**Derive `Debug` on almost all types.**

---

## Testing

**Use table-based tests with `test-case`:**

```rust
use test_case::test_case;

#[test_case("hello", "HELLO" ; "lowercase to upper")]
#[test_case("WORLD", "WORLD" ; "already upper")]
#[test_case("", "" ; "empty string")]
fn test_to_uppercase(input: &str, expected: &str) {
    assert_eq!(to_uppercase(input), expected);
}
```

---

## Logging with tracing

Use structured fields, not string interpolation:

```rust
// GOOD: Queryable structured data
tracing::info!(user_id = %user.id, action = "login", "user authenticated");

// AVOID: Unstructured, hard to query
tracing::info!("user {} logged in", user.id);
```

Use `#[tracing::instrument]` on functions, but skip sensitive or verbose data.

---

## Error Handling

**Always use `thiserror` for error types.**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("database query failed: {0}")]
    Database(#[from] sqlx::Error),

    #[error("user {user_id} not found")]
    UserNotFound { user_id: i64 },
}
```

**Avoid `anyhow` in application code.**

---

## Unsafe Code

Avoid `unsafe` when possible. When necessary, write `// SAFETY:` comments documenting requirements and how they're met.

---

## Project Setup

- Use `[profile.release]` with `lto = "fat"`, `codegen-units = 1`
- Use `[profile.distribute]` inheriting release with `strip = "symbols"`
- Use `build.rs` for git version injection and `cfg(distribute)` support
- Use nightly toolchain (`rust-toolchain.toml`)
- Use `.rustfmt.toml` with `edition = "2024"`, `max_width = 100`, `tab_spaces = 4`

---

## Trade-offs Reminder

Every rule here can be broken when the situation demands it. The goal is principled decisions, not rigid compliance. When you deviate, know why.
