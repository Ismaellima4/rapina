# Rapina 🦅

[![Crates.io](https://img.shields.io/crates/v/rapina.svg)](https://crates.io/crates/rapina)
[![Documentation](https://docs.rs/rapina/badge.svg)](https://docs.rs/rapina)
[![CI](https://github.com/arferreira/rapina/actions/workflows/ci.yml/badge.svg)](https://github.com/arferreira/rapina/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Predictable, auditable, and secure APIs — written by humans, accelerated by AI.

Rapina is a web framework for Rust inspired by FastAPI, focused on **productivity**, **type safety**, and **clear conventions**.

## Installation

Add Rapina to your `Cargo.toml`:

```toml
[dependencies]
rapina = "0.1"
```

## Why Rapina?

- **Opinionated** — Convention over configuration. 90% of apps require 10% of decisions.
- **Type-safe** — Typed extractors, typed errors, everything checked at compile time.
- **AI-friendly** — Predictable structure that humans and models understand.
- **Production-ready** — Standardized errors with `trace_id`, ready for observability.

## Quick Start

```rust
use rapina::prelude::*;

#[derive(Deserialize)]
struct CreateUser {
    name: String,
    email: String,
}

#[derive(Serialize)]
struct User {
    id: u64,
    name: String,
    email: String,
}

#[get("/")]
async fn hello() -> &'static str {
    "Hello, Rapina!"
}

#[get("/users/:id")]
async fn get_user(id: Path<u64>) -> Result<Json<User>> {
    let id = id.into_inner();

    if id == 0 {
        return Err(Error::not_found("user not found"));
    }

    Ok(Json(User {
        id,
        name: "Antonio".to_string(),
        email: "antonio@rust.dev".to_string(),
    }))
}

#[post("/users")]
async fn create_user(body: Json<CreateUser>) -> Json<User> {
    let input = body.into_inner();
    Json(User {
        id: 1,
        name: input.name,
        email: input.email,
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let router = Router::new()
        .get("/", hello)
        .get("/users/:id", get_user)
        .post("/users", create_user);

    Rapina::new()
        .router(router)
        .listen("127.0.0.1:3000")
        .await
}
```

## Features

### Typed Extractors

```rust
#[get("/users/:id")]
async fn get_user(id: Path<u64>) -> Json<User> { ... }

#[post("/users")]
async fn create_user(body: Json<CreateUser>) -> Json<User> { ... }

#[get("/search")]
async fn search(query: Query<SearchParams>) -> Json<Results> { ... }

#[post("/login")]
async fn login(form: Form<LoginData>) -> Json<Token> { ... }
```

Available extractors: `Json`, `Path`, `Query`, `Form`, `Headers`, `State`, `Context`

### Middleware

```rust
use rapina::middleware::{TimeoutMiddleware, BodyLimitMiddleware, TraceIdMiddleware};

Rapina::new()
    .middleware(TraceIdMiddleware::new())
    .middleware(TimeoutMiddleware::new(Duration::from_secs(30)))
    .middleware(BodyLimitMiddleware::new(1024 * 1024)) // 1MB
    .router(router)
    .listen("127.0.0.1:3000")
    .await
```

### Standardized Errors

Every error returns a consistent envelope with `trace_id`:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "user not found"
  },
  "trace_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Declarative Macros

```rust
#[get("/path")]
#[post("/path")]
#[put("/path")]
#[delete("/path")]
```

### Application State

```rust
#[derive(Clone)]
struct AppConfig {
    db_url: String,
}

#[get("/config")]
async fn get_config(state: State<AppConfig>) -> String {
    state.into_inner().db_url
}

Rapina::new()
    .state(AppConfig { db_url: "postgres://...".to_string() })
    .router(router)
    .listen("127.0.0.1:3000")
    .await
```

## Roadmap

- [x] Basic router
- [x] Extractors (`Json`, `Path`, `Query`, `Form`, `Headers`, `State`, `Context`)
- [x] Proc macros (`#[get]`, `#[post]`, `#[put]`, `#[delete]`)
- [x] Standardized error handling with `trace_id`
- [x] Middleware system (`Timeout`, `BodyLimit`, `TraceId`)
- [x] Dependency Injection / State
- [x] Request context with tracing
- [ ] Auth (Bearer JWT, `CurrentUser`)
- [ ] Observability (tracing, structured logs)
- [ ] Validation (`Validated<T>`)
- [ ] Automatic OpenAPI
- [ ] CLI (`rapina new`, `rapina routes`)

## Philosophy

Rapina is opinionated by design: a clear happy path, with escape hatches when needed.

| Principle | Description |
|-----------|-------------|
| Predictability | Clear conventions, obvious structure |
| Auditability | Typed contracts, traceable errors |
| Security | Guard rails by default |

## License

MIT
