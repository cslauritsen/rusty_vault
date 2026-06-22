/*
Copyright (c) 2026 Chad Lauritsen

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


use secrecy::ExposeSecret;
use rusty_vault::secure_value::SecureValue;
use rusty_vault::VaultClient;
use std::env;

fn live_tests_enabled() -> bool {
    matches!(
        std::env::var("RUN_VAULT_LIVE_TESTS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

#[tokio::test]
#[ignore = "requires live Vault access and may trigger browser OIDC login"]
async fn get_a_secret_live() {
    let _ = env_logger::builder().is_test(true).try_init();
    if !live_tests_enabled() {
        eprintln!("skipping live test; set RUN_VAULT_LIVE_TESTS=1 to enable");
        return;
    }

    let vc = VaultClient::default();
    if let Err(err) = vc.resolve_token().await {
        eprintln!("{}", err);
        panic!("resolve_token() should be OK");
    }

    let Ok(SecureValue::Object(secret)) = vc
        .fetch_secret(env::var("TEST_SECRET_API_PATH")
            .map_err(|e| format!("env var TEST_SECRET_API_PATH {:?}", e))
            .unwrap()
            .as_str())
        .await
    else {
        panic!("fetch_secret() should be OK");
    };

    let SecureValue::Secret(datum) = &secret[
        env::var("TEST_SECRET_FIELD_NAME")
        .unwrap()
        .as_str()
    ] else { todo!() };

    let prefix = env::var("TEST_SECRET_VALUE_PREFIX").unwrap();

    assert!(datum.expose_secret().starts_with(&prefix));
}
