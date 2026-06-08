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

use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use latch::{Latch, spin::Spin};
use log::debug;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{VaultClient, VaultClientErr};

const OIDC_CALLBACK_PORT: u16 = 8250;
const OIDC_ROLE: &str = "user";
const OIDC_HTML: &str = r#"
<!doctype html>
<html>
<head>
<script>
// Closes IE, Edge, Chrome, Brave
/*
window.onload = function load() {
  window.open('', '_self', '');
  window.close();
};
*/
</script>
</head>
<body>
  <p>Authentication successful, you can close the browser now.</p>
  <script>
    // Needed for Firefox security
    setTimeout(function() {
          window.close()
    }, 5000);
  </script>
</body>
</html>
"#;

#[derive(Clone)]
struct OidcCallbackState {
    latch: Arc<Latch<Spin>>,
    oauth_params: Arc<Mutex<OauthExchangeParams>>,
}

#[derive(Deserialize, Clone, Default)]
struct OauthExchangeParams {
    state: Option<String>,
    nonce: Option<String>,
    code: Option<String>,
}

impl VaultClient {
    async fn oidc_callback_get_handler(
        State(app_state): State<OidcCallbackState>,
        Query(OauthExchangeParams { state, nonce, code }): Query<OauthExchangeParams>,
    ) -> Html<&'static str> {
        {
            let mut p = app_state.oauth_params.lock().await;
            p.state = state;
            p.nonce = nonce;
            p.code = code;
        }

        app_state.latch.open();
        Html(OIDC_HTML)
    }

    /// Invokes the vault OIDC login flow and returns the issued token on success.
    pub(crate) async fn oidc_login(&self) -> Result<String, VaultClientErr> {
        let latch = Arc::new(Latch::<Spin>::new());
        let oauth_params = Arc::new(Mutex::new(OauthExchangeParams::default()));
        let app_state = OidcCallbackState {
            latch: Arc::clone(&latch),
            oauth_params: Arc::clone(&oauth_params),
        };
        let role = OIDC_ROLE.to_string();
        let redirect_uri = format!("http://localhost:{}/oidc/callback", OIDC_CALLBACK_PORT);

        let oidc_auth_url = format!("{}/v1/auth/oidc/oidc/auth_url", self.vault_addr);
        let oidc_auth_payload = serde_json::json!({
            "role": role,
            "redirect_uri": redirect_uri,
        });
        let auth_url_response = self
            .http_client
            .post(oidc_auth_url.as_str())
            .body(oidc_auth_payload.to_string())
            .send()
            .await?;
        let body = auth_url_response.text().await?;
        let auth_url_value: Value = serde_json::from_str(body.as_str())?;

        let target_url = auth_url_value["data"]["auth_url"]
            .to_string()
            .replace("\"", "");

        let addr: std::net::SocketAddr =
            format!("{}:{}", "127.0.0.1", OIDC_CALLBACK_PORT).parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;

        let app = Router::new()
            .route(
                "/oidc/callback",
                get(VaultClient::oidc_callback_get_handler),
            )
            .with_state(app_state);
        debug!("http server listening on {}", addr);

        open::that(&target_url)
            .map_err(|_| VaultClientErr::InvalidToken("failed to open browser for OIDC login"))?;
        debug!("opened browser to {}", target_url);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                latch.wait().await;
                debug!("Latch opened, shutting callback server down");
            })
            .await?;
        debug!("Server shut down");

        let params = oauth_params.lock().await.clone();
        let state = params
            .state
            .ok_or(VaultClientErr::MissingField("missing state in callback"))?;
        let code = params
            .code
            .ok_or(VaultClientErr::MissingField("missing code in callback"))?;
        let exchange_url = format!(
            "{}/v1/auth/oidc/oidc/callback?state={state}&code={code}",
            &self.vault_addr,
        );

        let resp = self.http_client.get(exchange_url.as_str()).send().await?;
        debug!("code exchange status {}", resp.status());

        let body = resp.text().await?;
        let body_value: Value = serde_json::from_str(body.as_str())?;
        let new_token = body_value["auth"]["client_token"]
            .to_string()
            .replace("\"", "");
        Ok(new_token)
    }
}
