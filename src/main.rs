use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, StatusCode},
    middleware,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

mod auth;
mod gee;

// Daftar provinsi / kabupaten (data nama saja) tetap publik
async fn get_wilayah_handler(
    State(pool): State<PgPool>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    if let Some(prov) = params.get("provinsi") {
        let query = r#"
            SELECT DISTINCT "WADMKK" AS kabupaten
            FROM batas_wilayah
            WHERE "WADMPR" = $1
            AND "WADMKK" IS NOT NULL
            AND "WADMKK" != ''
            ORDER BY kabupaten ASC;
        "#;

        let rows: Result<Vec<(String,)>, _> = sqlx::query_as(query)
            .bind(prov)
            .fetch_all(&pool)
            .await;

        match rows {
            Ok(data) => Json(serde_json::json!(
                data.into_iter().map(|r| r.0).collect::<Vec<String>>()
            )),
            Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
        }
    } else {
        let query = r#"
            SELECT DISTINCT "WADMPR" AS provinsi
            FROM batas_wilayah
            WHERE "WADMPR" IS NOT NULL AND "WADMPR" != ''
            ORDER BY provinsi ASC;
        "#;

        let rows: Result<Vec<(String,)>, _> = sqlx::query_as(query).fetch_all(&pool).await;

        match rows {
            Ok(data) => Json(serde_json::json!(
                data.into_iter().map(|r| r.0).collect::<Vec<String>>()
            )),
            Err(e) => Json(serde_json::json!({ "error": e.to_string() })),
        }
    }
}

// PROTEKSI: wajib login + memotong kredit (sekali per kabupaten per 24 jam)
async fn get_desa_handler(
    State(pool): State<PgPool>,
    Extension(user): Extension<auth::DbUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, auth::ApiError> {
    let kabupaten = params.get("kabupaten").ok_or_else(|| {
        auth::ApiError(StatusCode::BAD_REQUEST, "Pilih kabupaten terlebih dahulu.".into())
    })?;

    let query = r#"
        SELECT jsonb_build_object(
            'type',     'FeatureCollection',
            'features', COALESCE(jsonb_agg(features.feature), '[]'::jsonb)
        ) AS geojson
        FROM (
          SELECT jsonb_build_object(
            'type',       'Feature',
            'geometry',   ST_AsGeoJSON(geom)::jsonb,
            'properties', to_jsonb(inputs) - 'geom'
          ) AS feature
          FROM (
            SELECT * FROM batas_wilayah
            WHERE "WADMKK" = $1
          ) inputs
        ) features;
    "#;

    let row: (sqlx::types::Json<serde_json::Value>,) = sqlx::query_as(query)
        .bind(kabupaten)
        .fetch_one(&pool)
        .await?;

    // Kredit dipotong HANYA setelah data berhasil diambil
    auth::charge_peta(&pool, &user, kabupaten).await?;

    Ok(Json(row.0 .0))
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

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Gagal terhubung ke database. Periksa DATABASE_URL (termasuk ?sslmode=require untuk Aiven).");

    // Membuat tabel users, topup_requests, kredit_log, peta_akses bila belum ada
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
        .route("/api/auth/resend", post(auth::resend_code));

    // ---- Rute wajib login ----
    let protected = Router::new()
        .route("/api/me", get(auth::me))
        .route("/api/get-desa", get(get_desa_handler))
        .route("/api/ekspor", post(auth::cek_ekspor))
        .route(
            "/api/osm-cache",
            get(osm_cache_get_handler).post(osm_cache_post_handler),
        )
        .route("/api/gee-tiles", get(gee::gee_tiles))
        .route(
            "/api/topup",
            get(auth::topup_list_mine)
                .post(auth::topup_create)
                .layer(DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        // ---- Admin (dicek lagi di dalam handler) ----
        .route("/api/admin/topup", get(auth::admin_topup_list))
        .route("/api/admin/topup/:id/bukti", get(auth::admin_bukti))
        .route("/api/admin/topup/:id/approve", post(auth::admin_approve))
        .route("/api/admin/topup/:id/reject", post(auth::admin_reject))
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
