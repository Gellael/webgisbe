use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    middleware,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

mod auth;
mod gee;

// ===================== DATA DESA DARI BIG (tanpa database) =====================
// Batas desa/kelurahan tidak lagi disimpan di Aiven. Data diambil langsung dari layanan resmi BIG
// setiap kali dibutuhkan. Tabel `batas_wilayah` tidak dipakai lagi.
const BIG_LAYER_DESA: &str =
    "https://geoservices.big.go.id/rbi/rest/services/BATASWILAYAH/Administrasi_AR_KelDesa_10K/MapServer/0/query";

// Daftar provinsi -> kabupaten untuk dropdown. Dibuat SEKALI dari file .dbf lokal
// (jalankan tools/buat_wilayah.py), lalu disimpan di src/wilayah.json dan ikut ter-compile.
// Layer BIG tidak mendukung DISTINCT/paginasi, jadi daftar ini tidak bisa ditarik langsung darinya.
const WILAYAH_JSON: &str = include_str!("wilayah.json");

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(25))
            .build()
            .expect("Gagal membuat HTTP client")
    })
}

fn wilayah() -> &'static BTreeMap<String, Vec<String>> {
    static W: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();
    W.get_or_init(|| {
        serde_json::from_str(WILAYAH_JSON).expect("src/wilayah.json tidak valid")
    })
}

fn big_gagal() -> auth::ApiError {
    auth::ApiError(
        StatusCode::BAD_GATEWAY,
        "Layanan data batas wilayah (BIG) sedang tidak dapat dihubungi. Coba lagi beberapa saat.".into(),
    )
}

// Tanpa parameter  -> daftar provinsi
// ?provinsi=XXXX   -> daftar kabupaten/kota di provinsi itu
async fn get_wilayah_handler(
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let data = wilayah();
    match params.get("provinsi") {
        Some(prov) => Json(serde_json::json!(data.get(prov).cloned().unwrap_or_default())),
        None => Json(serde_json::json!(data.keys().collect::<Vec<_>>())),
    }
}

// PROTEKSI: wajib login + memiliki kredit (dicek di auth::charge_peta).
// Mengembalikan GeoJSON FeatureCollection seluruh desa dalam satu kabupaten (bentuk sama seperti sebelumnya).
async fn get_desa_handler(
    State(pool): State<PgPool>,
    Extension(user): Extension<auth::DbUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, auth::ApiError> {
    let kabupaten = params.get("kabupaten").ok_or_else(|| {
        auth::ApiError(StatusCode::BAD_REQUEST, "Pilih kabupaten terlebih dahulu.".into())
    })?;

    if kabupaten.is_empty() || kabupaten.chars().count() > 100 {
        return Err(auth::ApiError(StatusCode::BAD_REQUEST, "Nama kabupaten tidak valid.".into()));
    }

    // Tanda kutip tunggal digandakan agar nilai tidak bisa merusak klausa WHERE.
    let where_clause = format!("WADMKK = '{}'", kabupaten.replace('\'', "''"));

    let query = [
        ("where", where_clause.as_str()),
        ("outFields", "*"),
        ("outSR", "4326"),
        ("returnGeometry", "true"),
        ("returnZ", "false"),
        ("returnM", "false"),
        ("geometryPrecision", "6"),
        ("f", "geojson"),
    ];

    let resp = http_client()
        .get(BIG_LAYER_DESA)
        .query(&query)
        .send()
        .await
        .map_err(|e| {
            eprintln!("BIG request gagal: {e}");
            big_gagal()
        })?;

    if !resp.status().is_success() {
        eprintln!("BIG membalas status {}", resp.status());
        return Err(big_gagal());
    }

    let geojson: serde_json::Value = resp.json().await.map_err(|e| {
        eprintln!("Balasan BIG bukan JSON valid: {e}");
        big_gagal()
    })?;

    // ArcGIS kadang membalas HTTP 200 dengan {"error": {...}}
    let punya_fitur = geojson.get("features").map_or(false, |f| f.is_array());
    if geojson.get("error").is_some() || !punya_fitur {
        eprintln!("Balasan BIG tidak berisi features: {}", geojson.get("error").unwrap_or(&serde_json::Value::Null));
        return Err(big_gagal());
    }

    // Batas per permintaan layer ini 4000 fitur dan tanpa paginasi. Kabupaten terbesar jauh di bawah itu,
    // tetapi bila suatu saat terlampaui, hasil terpotong dan perlu ditangani.
    if geojson.get("exceededTransferLimit").and_then(|v| v.as_bool()).unwrap_or(false) {
        eprintln!("PERINGATAN: hasil BIG untuk '{}' terpotong (exceededTransferLimit)", kabupaten);
    }

    // Pengecekan kredit dilakukan SETELAH data berhasil diambil (seperti sebelumnya).
    auth::charge_peta(&pool, &user, kabupaten).await?;

    Ok(Json(geojson))
}

#[derive(Deserialize)]
struct OsmCachePayload {
    area: String,
    osm_json: serde_json::Value,
}

async fn osm_cache_get_handler(
    State(pool): State<PgPool>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let area = match params.get("area") {
        Some(a) => a,
        None => {
            return Json(serde_json::json!({ "success": false, "message": "Area parameter missing" }))
        }
    };

    let row: Result<(serde_json::Value,), _> =
        sqlx::query_as("SELECT osm_json FROM osm_cache WHERE area_id = $1 LIMIT 1")
            .bind(area)
            .fetch_one(&pool)
            .await;

    match row {
        Ok(data) => Json(serde_json::json!({ "success": true, "data": data.0 })),
        Err(_) => Json(serde_json::json!({ "success": false, "message": "Cache not found" })),
    }
}

async fn osm_cache_post_handler(
    State(pool): State<PgPool>,
    Json(payload): Json<OsmCachePayload>,
) -> Json<serde_json::Value> {
    let res = sqlx::query(
        r#"
        INSERT INTO osm_cache (area_id, osm_json)
        VALUES ($1, $2)
        ON CONFLICT (area_id)
        DO UPDATE SET osm_json = EXCLUDED.osm_json, created_at = CURRENT_TIMESTAMP
    "#,
    )
    .bind(payload.area)
    .bind(payload.osm_json)
    .execute(&pool)
    .await;

    match res {
        Ok(_) => Json(serde_json::json!({ "success": true, "message": "Saved to Aiven cache" })),
        Err(e) => Json(serde_json::json!({ "success": false, "error": e.to_string() })),
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL belum diset. Isi di file .env atau environment server.");

    // Gagal cepat bila JWT_SECRET belum diset
    auth::jwt_secret();

    // Dikonfigurasi untuk serverless (Vercel): instance dibekukan di antara request, jadi koneksi yang
    // menganggur cepat basi. Pool kecil + koneksi dibuang lebih cepat + gagal cepat (bukan menunggu 30 dtk)
    // supaya tidak menghabiskan batas koneksi Aiven dan tidak menggantung.
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(15))
        .max_lifetime(Duration::from_secs(240))
        .test_before_acquire(true)
        .connect(&database_url)
        .await
        .expect("Gagal terhubung ke database. Periksa DATABASE_URL (termasuk ?sslmode=require untuk Aiven).");

    // Membuat tabel users, kredit_log, peta_akses (dan topup_requests lama) bila belum ada
    auth::ensure_schema(&pool)
        .await
        .expect("Gagal membuat tabel autentikasi.");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    // ---- Rute publik ----
    let public = Router::new()
        .route("/api/get-wilayah", get(get_wilayah_handler))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/verify", post(auth::verify_email))   
        .route("/api/auth/resend", post(auth::resend_code))
        .route("/api/auth/forgot", post(auth::forgot_password))
        .route("/api/auth/reset", post(auth::reset_password));
    let protected = Router::new()
        .route("/api/me", get(auth::me))
        .route("/api/get-desa", get(get_desa_handler))
        .route("/api/ekspor", post(auth::cek_ekspor))
        .route(
            "/api/osm-cache",
            get(osm_cache_get_handler).post(osm_cache_post_handler),
        )
        .route("/api/gee-tiles", get(gee::gee_tiles))
        // ---- Admin (dicek lagi di dalam handler) ----
        .route("/api/admin/users", get(auth::admin_users_search))
        .route("/api/admin/kredit", post(auth::admin_add_kredit))
        .route_layer(middleware::from_fn_with_state(pool.clone(), auth::require_auth));

    let app = Router::new()
        .merge(public)
        .merge(protected)
        .layer(cors)
        .with_state(pool);

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("HOST/PORT tidak valid");

    println!("🚀 Backend Rust berjalan di http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}