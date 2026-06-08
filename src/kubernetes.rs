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

use log::debug;
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};
use std::env;

use crate::secure_value::SecureValue;
use crate::{VaultClient, VaultClientErr};

/// Default path where Kubernetes injects the service account JWT.
const K8S_SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

impl VaultClient {
    /// Returns `true` when the process appears to be running inside a Kubernetes pod,
    /// i.e. the service account token file is present on disk.
    pub fn is_kubernetes_env() -> bool {
        std::path::Path::new(K8S_SA_TOKEN_PATH).exists()
    }

    /// Logs into Vault using the [Kubernetes auth method] and returns the issued
    /// client token on success.
    ///
    /// Configuration is read from environment variables:
    ///
    /// | Variable              | Default      | Description                                      |
    /// |-----------------------|--------------|--------------------------------------------------|
    /// | `VAULT_K8S_ROLE`      | *(required)* | Vault role name bound to the Kubernetes SA       |
    /// | `VAULT_K8S_AUTH_PATH` | `kubernetes` | Mount path of the Kubernetes auth method in Vault|
    /// | `VAULT_K8S_SA_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Override for the service account JWT file path |
    ///
    /// [Kubernetes auth method]: https://developer.hashicorp.com/vault/docs/auth/kubernetes
    pub async fn kubernetes_login(&self) -> Result<SecretString, VaultClientErr> {
        let role = env::var("VAULT_K8S_ROLE").map_err(|_| {
            VaultClientErr::InvalidToken("VAULT_K8S_ROLE env var is required for Kubernetes login")
        })?;

        let auth_path =
            env::var("VAULT_K8S_AUTH_PATH").unwrap_or_else(|_| String::from("kubernetes"));

        let sa_token_path =
            env::var("VAULT_K8S_SA_TOKEN_PATH").unwrap_or_else(|_| String::from(K8S_SA_TOKEN_PATH));

        let mut jwt_plain = std::fs::read_to_string(&sa_token_path).map_err(|e| {
            debug!("failed to read Kubernetes service account token from {sa_token_path}: {e}");
            VaultClientErr::Io(e)
        })?;

        let jwt = SecretString::from(jwt_plain.trim());
        jwt_plain.zeroize();

        let login_url = format!(
            "{}/v1/auth/{}/login",
            self.vault_addr,
            auth_path.trim_matches('/')
        );

        let payload = serde_json::json!({
            "jwt":  jwt.expose_secret(),
            "role": role,
        });

        debug!("attempting Kubernetes vault login at {login_url} with role={role}");

        let resp = self
            .http_client
            .post(&login_url)
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await?;

        let status = resp.status();
        debug!("Kubernetes login response status={status}");

        if !status.is_success() {
            return Err(VaultClientErr::InvalidToken(
                "Kubernetes login request failed",
            ));
        }

        let mut body = resp.text().await?;
        let body_value: SecureValue = serde_json::from_str(&body)?;
        body.zeroize();
        Self::parse_kubernetes_login_token(body_value)
    }

    /// Pull `auth.client_token` from a Vault Kubernetes login response represented as SecureValue.
    fn parse_kubernetes_login_token(body: SecureValue) -> Result<SecretString, VaultClientErr> {
        let SecureValue::Object(mut root) = body else {
            return Err(VaultClientErr::MissingField(
                "auth.client_token missing in Kubernetes login response",
            ));
        };

        let SecureValue::Object(mut auth) = root.remove("auth").ok_or(
            VaultClientErr::MissingField("auth.client_token missing in Kubernetes login response"),
        )?
        else {
            return Err(VaultClientErr::MissingField(
                "auth.client_token missing in Kubernetes login response",
            ));
        };

        match auth
            .remove("client_token")
            .ok_or(VaultClientErr::MissingField(
                "auth.client_token missing in Kubernetes login response",
            ))? {
            SecureValue::Secret(token) => Ok(token),
            SecureValue::PlainString(token) => Ok(SecretString::from(token)),
            _ => Err(VaultClientErr::MissingField(
                "auth.client_token missing in Kubernetes login response",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kubernetes_login_token_extracts_nested_token() {
        let body = serde_json::from_str::<SecureValue>(
            r#"{"auth":{"client_token":"s.yep-this-is-a-token"}}"#,
        )
        .expect("valid json");

        let token =
            VaultClient::parse_kubernetes_login_token(body).expect("token should be parsed");
        assert_eq!(token.expose_secret(), "s.yep-this-is-a-token");
    }

    #[test]
    fn parse_kubernetes_login_token_rejects_missing_token() {
        let body = serde_json::from_str::<SecureValue>(r#"{"auth":{}}"#).expect("valid json");

        let err = VaultClient::parse_kubernetes_login_token(body)
            .expect_err("should fail when token missing");
        assert!(matches!(
            err,
            VaultClientErr::MissingField("auth.client_token missing in Kubernetes login response")
        ));
    }
}
