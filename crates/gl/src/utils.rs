use anyhow::{bail, Result};
use reqwest::Response;
use serde::de::DeserializeOwned;

/// Parse a JSON response, ensuring the HTTP status is successful.
///
/// On a non‑2xx status, the function will bail with a clear error
/// containing the status code and response body.
pub async fn handle_response<T: DeserializeOwned>(resp: Response) -> Result<T> {
    if !resp.status().is_success() {
        // Preserve the full response text for diagnostics.
        let body = resp.text().await.unwrap_or_default();
        bail!("list failed ({}): {}", resp.status(), body.trim());
    }
    resp.json::<T>().await
}