use axum::{extract::Query, http::StatusCode, Json};
use gcp_auth::{CustomServiceAccount, TokenProvider};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct GeeQuery {
    pub layer: Option<String>,
}

pub async fn gee_tiles(
    Query(q): Query<GeeQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let layer = q.layer.unwrap_or_else(|| "elevation".to_string());

    // Daftar layer yang diizinkan. Tambah layer baru di sini.
    let graph = match layer.as_str() {
        "ndwi" => include_str!("../gee/ndwi.json"),
        "ndvi" => include_str!("../gee/ndvi.json"),
        "elevation" => include_str!("../gee/elevation.json"),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "layer tidak dikenal" })),
            ))
        }
    };

    match build_tile_url(graph).await {
        Ok(url) => Ok(Json(json!({ "tileUrl": url }))),
        Err(e) => {
            eprintln!("GEE error: {e:#}"); // terlihat di Vercel Logs
            Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "gagal membuat tile Earth Engine" })),
            ))
        }
    }
}

async fn build_tile_url(graph_json: &str) -> anyhow::Result<String> {
    let key_json = std::env::var("GEE_SERVICE_ACCOUNT_JSON")?;
    let project = std::env::var("GEE_PROJECT_ID")?;

    let sa = CustomServiceAccount::from_json(&key_json)?;
    let token = sa
        .token(&["https://www.googleapis.com/auth/earthengine"])
        .await?;

    let expression: Value = serde_json::from_str(graph_json)?;

    let resp = reqwest::Client::new()
        .post(format!(
            "https://earthengine.googleapis.com/v1/projects/{project}/maps"
        ))
        .bearer_auth(token.as_str())
        .json(&json!({ "expression": expression, "fileFormat": "PNG" }))
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("Earth Engine {status}: {text}");
    }

    let v: Value = serde_json::from_str(&text)?;
    let name = v["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("respons tanpa field name: {text}"))?;

    Ok(format!(
        "https://earthengine.googleapis.com/v1/{name}/tiles/{{z}}/{{x}}/{{y}}"
    ))
}