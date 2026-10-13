use gcp_auth::{CustomServiceAccount, TokenProvider};
use serde_json::{json, Value};
use vercel_runtime::{run, Body, Error, Request, Response, StatusCode};

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(handler).await
}

fn reply(status: StatusCode, body: Value) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*") // ganti dengan domain frontend kamu bila perlu
        .header("Access-Control-Allow-Methods", "GET, OPTIONS")
        .header("Cache-Control", "no-store")
        .body(Body::Text(body.to_string()))?)
}

pub async fn handler(req: Request) -> Result<Response<Body>, Error> {
    if req.method() == "OPTIONS" {
        return reply(StatusCode::NO_CONTENT, json!({}));
    }

    let layer = req
        .uri()
        .query()
        .and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "layer")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_else(|| "elevation".to_string());

    // Daftar layer yang diizinkan. Tambah layer baru di sini.
    let graph = match layer.as_str() {
        "elevation" => include_str!("../gee/elevation.json"),
        _ => return reply(StatusCode::BAD_REQUEST, json!({ "error": "layer tidak dikenal" })),
    };

    match build_tile_url(graph).await {
        Ok(url) => reply(StatusCode::OK, json!({ "tileUrl": url })),
        Err(e) => {
            eprintln!("GEE error: {e:#}"); // terlihat di Vercel Logs
            reply(StatusCode::BAD_GATEWAY, json!({ "error": "gagal membuat tile Earth Engine" }))
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

let expression: Value = match serde_json::from_str::<Value>(graph_json.trim())? {
    Value::String(inner) => serde_json::from_str(&inner)?, // hasil copy dari Console GEE
    other => other,                                       // JSON biasa
};

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