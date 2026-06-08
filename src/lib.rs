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
pub mod secure_value;

#[cfg(feature = "oidc_callback")]
mod oidc;

mod kubernetes;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::VaultClientErr::{InvalidSecret, InvalidToken};
use crate::secure_value::SecureValue;
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::env;
use std::net::AddrParseError;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;

static METHOD_GATE: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Debug, thiserror::Error)]
pub enum VaultClientErr {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("json error: {0}")]
    AddrParse(#[from] AddrParseError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("missing callback field: {0}")]
    MissingField(&'static str),

    #[error("invalid token: {0}")]
    InvalidToken(&'static str),

    #[error("invalid secret: {0}")]
    InvalidSecret(&'static str),
}

#[derive(Debug)]
pub struct VaultClient {
    vault_addr: String,
    http_client: reqwest::Client,
    token: Arc<Mutex<Option<SecretString>>>,
}

impl Default for VaultClient {
    fn default() -> Self {
        Self {
            vault_addr: env::var("VAULT_ADDR")
                .unwrap_or_else(|_| String::from("http://localhost:8200"))
                .trim_end_matches('/')
                .to_string(),
            http_client: reqwest::Client::new(),
            token: Arc::new(Mutex::new(None)),
        }
    }
}

impl VaultClient {
    async fn lookup_self(&self, token: &SecretString) -> Result<bool, VaultClientErr> {
        let url = format!("{}/{}", self.vault_addr, "v1/auth/token/lookup-self");
        let response = self
            .http_client
            .get(url.as_str())
            .header("x-vault-token", token.expose_secret())
            .send()
            .await?;
        Ok(response.status().is_success())
    }

    #[cfg(not(feature = "oidc_callback"))]
    async fn oidc_login(&self) -> Result<String, VaultClientErr> {
        Err(InvalidToken("oidc_callback feature is disabled"))
    }

    #[cfg(unix)]
    async fn chmod(path: impl AsRef<std::path::Path>, mode: u32) -> Result<(), VaultClientErr> {
        fs::set_permissions(path, PermissionsExt::from_mode(mode)).await?;
        Ok(())
    }

    #[cfg(not(unix))]
    async fn chmod(_path: impl AsRef<std::path::Path>, _mode: u32) -> Result<(), VaultClientErr> {
        Ok(())
    }

    async fn save_token(&self) -> () {
        if let Some(home) = dirs::home_dir() {
            let token_file = home.join(".vault-token");
            if let Some(token_val) = self.token.lock().await.as_ref() {
                match fs::write(&token_file, token_val.expose_secret()).await {
                    Ok(()) => {
                        Self::chmod(&token_file, 0o600).await.ok();
                        info!("Saved token to {}", token_file.display());
                    }
                    Err(e) => {
                        warn!("Ignoring failed attempt to save token to ~/.vault-token {e}");
                    }
                }
            } else {
                warn!("token empty, not saved");
            }
        }
    }

    async fn replace_token(&self, newtok: &SecretString) {
        self.token.lock().await.replace(newtok.clone());
    }

    fn env_token(&self) -> Option<SecretString> {
        if let Ok(mut token) = env::var("VAULT_TOKEN") {
            let secret = SecretString::from(token.trim());
            token.zeroize();
            return Some(secret);
        }
        None
    }

    /// Resolve a vault token.
    /// First, try see if there's a `VAULT_TOKEN` enviroment variable
    /// then try to validate it. if it's good, use it.
    /// Else try to load `~/.vault-token`
    /// then try to validate it, if it's good, use it.
    /// Then try to get one via OIDC
    ///  if that works, return the token in the result
    /// Otherwise, return an error
    pub async fn resolve_token(&self) -> Result<SecretString, VaultClientErr> {
        if let Some(secret) = self.env_token()
            && let Ok(validated) = self.lookup_self(&secret).await
            && validated
        {
            info!("Using token from VAULT_TOKEN environment variable");
            self.replace_token(&secret).await;
            // since we loaded the token from the environment, i don't think it makes sense
            // to be fanatical about wiping memory
            return Ok(secret);
        }

        // try ~/.vault-token, if found
        if let Some(home) = dirs::home_dir() {
            let token_file = home.join(".vault-token");
            if let Ok(mut plaintext) = std::fs::read_to_string(&token_file) {
                let token = SecretString::from(plaintext.trim());
                plaintext.zeroize(); // zeroize the plaintext copy as soon as possible
                if let Ok(validated) = self.lookup_self(&token).await
                    && validated
                {
                    self.replace_token(&token).await;
                    return Ok(token);
                }
            }
        }

        if Self::is_kubernetes_env() {
            info!("Attempting kubernetes vault login...");
            if let Ok(k8s_tok) = self.kubernetes_login().await {
                info!("Kubernetes login successful, collecting token");
                self.replace_token(&k8s_tok).await;
                return Ok(k8s_tok);
            }
        }

        #[cfg(feature = "oidc_callback")]
        if !Self::is_kubernetes_env() {
            info!("Attempting OIDC vault login...");
            if let Ok(oidc_tok) = self.oidc_login().await {
                info!("OIDC login successful, collecting token");
                let token = SecretString::from(oidc_tok.trim());
                self.replace_token(&token).await;
                self.save_token().await;
                return Ok(token);
            }
        }

        // any token we have is no good, remove it
        self.token.lock().await.take();
        Err(InvalidToken(
            "no valid token found via env, file, Kubernetes, or OIDC login",
        ))
    }

    /// Fetches a secret from vault as a map of strings. Discards any values that are not scalar.
    /// If your secret contains complex types, use [`VaultClient::fetch_secret`] instead.
    pub async fn fetch_secret_as_simple_map(
        &self,
        api_path: &str,
    ) -> Result<HashMap<String, Option<SecretString>>, VaultClientErr> {
        let value = self.fetch_secret(api_path).await?;
        let mut result = HashMap::new();
        if let SecureValue::Object(map) = value {
            for (k, v) in map {
                match v {
                    SecureValue::Secret(x) => result.insert(k, Some(SecretString::from(x))),
                    SecureValue::Number(x) => {
                        result.insert(k, Some(SecretString::from(x.to_string())))
                    }
                    SecureValue::Bool(x) => {
                        result.insert(k, Some(SecretString::from(x.to_string())))
                    }
                    _ => result.insert(k, None),
                };
            }
            Ok(result)
        } else {
            Err(InvalidSecret("secret value is not a string"))
        }
    }

    pub async fn fetch_secret(&self, api_path: &str) -> Result<SecureValue, VaultClientErr> {
        if let Some(token) = self.token.lock().await.as_ref() {
            debug!("fetching secret at path {api_path}");
            let url = format!(
                "{}/{}",
                self.vault_addr,
                api_path.trim().trim_start_matches('/')
            );
            let mut plain_json = self
                .http_client
                .get(url)
                .header("x-vault-token", token.expose_secret())
                .send()
                .await?
                .text()
                .await?;
            let secure_json = SecretString::from(plain_json.as_str());
            plain_json.zeroize();
            // if let Object(value) = serde_json::from_str::<Value>(&json_str)? {
            if let Ok(parse_result) =
                serde_json::from_str::<SecureValue>(secure_json.expose_secret())
                && let SecureValue::Object(mut value) = parse_result
                && let Some(SecureValue::Object(mut outer_data)) = value.remove("data")
                && let Some(inner_data) = outer_data.remove("data")
            {
                return Ok(inner_data);
            }
            Err(InvalidSecret("secret of unexpected shape"))
        } else {
            Err(InvalidToken("invalid token"))
        }
    }
}

pub async fn env_secret_and_remove(env_var_name: &str) -> Option<SecretString> {
    let _guard = METHOD_GATE.lock().await;

    let mut plain = env::var(env_var_name).ok()?;
    let secret = SecretString::from(plain.as_str());
    plain.zeroize();
    unsafe {
        env::remove_var(env_var_name); // reduce window where value remains in env
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_client_starts_with_empty_cached_token() {
        let vc = VaultClient::default();
        assert!(vc.token.lock().await.is_none());
    }
}
