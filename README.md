# rusty_vault

A Rust client library for [HashiCorp Vault](https://www.vaultproject.io/).

## Features

- **Automatic token resolution** — checks `VAULT_TOKEN` env var, then `~/.vault-token`
- **OIDC login flow (optional)** — when the `oidc_callback` feature is enabled, starts a local callback server (port
  8250), opens the browser, and exchanges the authorization code for a Vault token automatically
- **Token persistence** — saves a freshly acquired OIDC token to `~/.vault-token` (chmod 600 on Unix)
- **Secret fetching** — retrieves KV v2 secrets as raw `serde_json::Value` or as a flat
  `HashMap<String, Option<String>>`

## Optional `oidc_callback` Feature

OIDC support and its callback dependencies are gated behind the `oidc_callback` feature.

Without the feature, `resolve_token()` checks only:

1. `VAULT_TOKEN`
2. `~/.vault-token`

To enable browser OIDC fallback:

```toml
[dependencies]
rusty_vault = { git = "https://github.com/cslauritsen/rusty_vault", features = ["oidc_callback"] }
tokio = { version = "1", features = ["full"] }
```

## Quick Start

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
rusty_vault = { git = "https://github.com/sherwin-williams-co/rusty_vault", features = ["oidc_callback"] }
tokio = { version = "1", features = ["full"] }
```

## Usage

```rust
use rusty_vault::VaultClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = VaultClient::default();

    // Resolve a token (env → file → OIDC browser login when enabled)
    client.resolve_token().await?;

    // Fetch a KV v2 secret as a HashMap
    let secrets = client
        .fetch_secret_as_simple_map("v1/my-namespace/kv2/data/my-app/prod")
        .await?;

    println!("db_password = {:?}", secrets.get("db_password"));

    Ok(())
}
```

### Fetch raw JSON

```rust
let value = client.fetch_secret("v1/my-namespace/kv2/data/my-app/prod").await?;
println!("{}", value["some_key"]);
```

## Configuration

| Environment Variable | Default                 | Description                                      |
|----------------------|-------------------------|--------------------------------------------------|
| `VAULT_ADDR`         | `http://localhost:8200` | Base URL of the Vault server                     |
| `VAULT_TOKEN`        | *(none)*                | Token to use directly, skipping file/OIDC lookup |

## Token Resolution Order

1. `VAULT_TOKEN` environment variable — validated against Vault before use
2. `~/.vault-token` file — validated against Vault before use
3. OIDC browser login *(only when `oidc_callback` is enabled)* — opens the Vault auth flow in a browser; token is saved
   to `~/.vault-token` on success

## Error Handling

All public async methods return `Result<_, VaultClientErr>`, covering HTTP errors, JSON parsing failures, missing
callback fields, invalid tokens, and I/O errors.

## Running Tests

Unit tests run with the standard `cargo test`.

Integration tests in `tests/vault_live.rs` require live Vault access and are skipped by default.

You can opt to run all live tests with OIDC enabled. For example: 


```bash
export TEST_SECRET_API_PATH=/v1/my_mount/data/foo/bar/baz
export TEST_SECRET_FIELD_NAME=quux
export TEST_SECRET_VALUE_PREFIX=abc123
export RUN_VAULT_LIVE_TESTS=1 
cargo test --features oidc_callback -- --include-ignored
```
The above will test that the value returned from the equivalent vault CLI command:

    vault kv get -field quux -mount my_mount foo/bar/baz

starts with the string `abc123`

Run only the OIDC live test (with output):

```bash
RUN_VAULT_LIVE_TESTS=1 cargo test --features oidc_callback --test vault_live run_oidc_flow -- --nocapture
```

> **Note:** The OIDC live test will open a browser window to complete authentication.

## License

MIT License. See [LICENSE](LICENSE) for details.
