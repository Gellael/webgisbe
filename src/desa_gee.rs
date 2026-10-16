//! Mengambil batas desa dari Asset Earth Engine milik sendiri (alternatif/cadangan layanan BIG).
//!
//! Dipakai oleh `get_desa_handler` di main.rs. Modul ini berdiri sendiri dan tidak memakai fungsi di gee.rs.
//! Konfigurasi lewat .env (semua opsional, ada nilai bawaan):
//!   GEE_KEY_FILE     path file kunci service account      (bawaan: gee-key.json)
//!   GEE_PROJECT      ID project Google Cloud               (bawaan: project-gis-494114)
//!   GEE_ASSET_DESA   ID asset tabel desa                   (bawaan: projects/<GEE_PROJECT>/assets/batas_desa)
use gcp_auth::{CustomServiceAccount, TokenProvider};
use serde_json::{json, Value};
use std::env;
use tokio::sync::OnceCell;

const SCOPE: &[&str] = &["https://www.googleapis.com/auth/earthengine"];
const UKURAN_HALAMAN: u32 = 1000;
const MAKS_HALAMAN: usize = 20; // pengaman: maksimal 20.000 fitur per permintaan

static AKUN: OnceCell<CustomServiceAccount> = OnceCell::const_new();

fn project() -> String {
    env::var("GEE_PROJECT").unwrap_or_else(|_| "project-gis-494114".to_string())
}

fn asset_desa() -> String {
    env::var("GEE_ASSET_DESA")
        .unwrap_or_else(|_| format!("projects/{}/assets/batas_desa", project()))
}

async fn akun() -> anyhow::Result<&'static CustomServiceAccount> {
    AKUN.get_or_try_init(|| async {
        let path = env::var("GEE_KEY_FILE").unwrap_or_else(|_| "gee-key.json".to_string());
        let akun = CustomServiceAccount::from_file(&path)
            .map_err(|e| anyhow::anyhow!("Gagal membaca kunci GEE '{path}': {e}"))?;
        Ok::<_, anyhow::Error>(akun)
    })
    .await
}

/// Ekspresi Earth Engine untuk: ee.FeatureCollection(ASET).filter(ee.Filter.eq('WADMKK', kabupaten))
fn ekspresi_kabupaten(kabupaten: &str) -> Value {
    json!({
        "result": "0",
        "values": {
            "0": {
                "functionInvocationValue": {
                    "functionName": "Collection.filter",
                    "arguments": {
                        "collection": {
                            "functionInvocationValue": {
                                "functionName": "Collection.loadTable",
                                "arguments": { "tableId": { "constantValue": asset_desa() } }
                            }
                        },
                        "filter": {
                            "functionInvocationValue": {
                                "functionName": "Filter.equals",
                                "arguments": {
                                    "leftField": { "constantValue": "WADMKK" },
                                    "rightValue": { "constantValue": kabupaten }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Mengembalikan GeoJSON FeatureCollection seluruh desa di satu kabupaten/kota.
pub async fn ambil_desa(client: &reqwest::Client, kabupaten: &str) -> anyhow::Result<Value> {
    let token = akun().await?.token(SCOPE).await?;
    let url = format!(
        "https://earthengine.googleapis.com/v1/projects/{}/table:computeFeatures",
        project()
    );
    let ekspresi = ekspresi_kabupaten(kabupaten);

    let mut fitur: Vec<Value> = Vec::new();
    let mut page_token: Option<String> = None;

    for _ in 0..MAKS_HALAMAN {
        let mut body = json!({ "expression": ekspresi, "pageSize": UKURAN_HALAMAN });
        if let Some(t) = &page_token {
            body["pageToken"] = json!(t);
        }

        let resp = client
            .post(&url)
            .bearer_auth(token.as_str())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let teks = resp.text().await?;
        if !status.is_success() {
            let ringkas: String = teks.chars().take(300).collect();
            anyhow::bail!("GEE membalas {status}: {ringkas}");
        }

        let v: Value = serde_json::from_str(&teks)?;
        if let Some(arr) = v.get("features").and_then(|f| f.as_array()) {
            fitur.extend(arr.iter().cloned());
        }
        page_token = v
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty())
            .map(String::from);
        if page_token.is_none() {
            break;
        }
    }

    Ok(json!({ "type": "FeatureCollection", "features": fitur }))
}
