use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Multipart, Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    collections::HashMap,
    env,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    nama          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    kredit        INTEGER NOT NULL DEFAULT 0 CHECK (kredit >= 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS topup_requests (
    id               BIGSERIAL PRIMARY KEY,
    user_id          BIGINT NOT NULL REFERENCES users(id),
    nominal          BIGINT NOT NULL,
    catatan          TEXT,
    bukti            BYTEA NOT NULL,
    bukti_mime       TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    kredit_diberikan INTEGER,
    alasan_admin     TEXT,
    reviewed_by      BIGINT REFERENCES users(id),
    reviewed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_topup_status ON topup_requests(status, id DESC);

CREATE TABLE IF NOT EXISTS kredit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id),
    delta      INTEGER NOT NULL,
    alasan     TEXT NOT NULL,
    ref        TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS peta_akses (
    user_id    BIGINT NOT NULL REFERENCES users(id),
    kabupaten  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, kabupaten)
);
"#;

pub async fn ensure_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(SCHEMA).execute(pool).await?;
    Ok(())
}

// ===================== ERROR =====================
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    fn bad(msg: &str) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.to_string())
    }
    fn unauth() -> Self {
        ApiError(StatusCode::UNAUTHORIZED, "Silakan masuk terlebih dahulu.".into())
    }
    fn server() -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Terjadi kesalahan server.".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        eprintln!("DB error: {e}");
        ApiError::server()
    }
}

// ===================== MODEL =====================
#[derive(sqlx::FromRow, Clone)]
pub struct DbUser {
    pub id: i64,
    pub email: String,
    pub nama: String,
    pub password_hash: String,
    pub role: String,
    pub kredit: i32,
}

#[derive(Serialize)]
pub struct UserOut {
    id: i64,
    email: String,
    nama: String,
    role: String,
    kredit: i32,
}

impl From<DbUser> for UserOut {
    fn from(u: DbUser) -> Self {
        UserOut { id: u.id, email: u.email, nama: u.nama, role: u.role, kredit: u.kredit }
    }
}

#[derive(Serialize)]
pub struct AuthResp {
    token: String,
    user: UserOut,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TopupOut {
    id: i64,
    email: String,
    nama: String,
    nominal: i64,
    catatan: Option<String>,
    status: String,
    kredit_diberikan: Option<i32>,
    alasan_admin: Option<String>,
    dibuat: String,
}

const TOPUP_SELECT: &str = r#"
    SELECT t.id, u.email, u.nama, t.nominal, t.catatan, t.status,
           t.kredit_diberikan, t.alasan_admin,
           to_char(t.created_at AT TIME ZONE 'Asia/Jakarta', 'DD Mon YYYY HH24:MI') AS dibuat
    FROM topup_requests t
    JOIN users u ON u.id = t.user_id
"#;

// ===================== JWT & PASSWORD =====================
pub fn jwt_secret() -> &'static str {
    static S: OnceLock<String> = OnceLock::new();
    S.get_or_init(|| {
        let s = env::var("JWT_SECRET").expect("JWT_SECRET belum diset di .env");
        assert!(s.len() >= 32, "JWT_SECRET minimal 32 karakter");
        s
    })
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i64,
    exp: usize,
}

fn make_token(user_id: i64) -> Result<String, ApiError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| ApiError::server())?.as_secs();
    let claims = Claims { sub: user_id, exp: (now + 7 * 24 * 3600) as usize };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret().as_bytes()))
        .map_err(|_| ApiError::server())
}

async fn hash_pw(pw: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string())
    })
    .await
    .map_err(|_| ApiError::server())?
    .map_err(|_| ApiError::server())
}

async fn verify_pw(pw: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|p| Argon2::default().verify_password(pw.as_bytes(), &p).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

// ===================== MIDDLEWARE =====================
pub async fn require_auth(
    State(pool): State<PgPool>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauth)?;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| ApiError::unauth())?;

    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE id = $1",
    )
    .bind(data.claims.sub)
    .fetch_optional(&pool)
    .await?;

    let user = user.ok_or_else(ApiError::unauth)?;
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

fn require_admin(user: &DbUser) -> Result<(), ApiError> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(ApiError(StatusCode::FORBIDDEN, "Khusus admin.".into()))
    }
}

// ===================== REGISTER / LOGIN / ME =====================
#[derive(Deserialize)]
pub struct RegisterReq {
    email: String,
    nama: String,
    password: String,
}

pub async fn register(
    State(pool): State<PgPool>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<AuthResp>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let nama = req.nama.trim().to_string();
    if !email.contains('@') || email.len() > 120 {
        return Err(ApiError::bad("Email tidak valid."));
    }
    if nama.is_empty() || nama.chars().count() > 80 {
        return Err(ApiError::bad("Nama wajib diisi (maksimal 80 karakter)."));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(ApiError::bad("Kata sandi 8-128 karakter."));
    }

    let hash = hash_pw(req.password).await?;
    // Email di ADMIN_EMAIL otomatis menjadi admin saat mendaftar
    let is_admin = env::var("ADMIN_EMAIL")
        .map(|a| a.trim().to_lowercase() == email)
        .unwrap_or(false);
    let role = if is_admin { "admin" } else { "user" };

    let row = sqlx::query_as::<_, DbUser>(
        "INSERT INTO users (email, nama, password_hash, role) VALUES ($1, $2, $3, $4)
         RETURNING id, email, nama, password_hash, role, kredit",
    )
    .bind(&email)
    .bind(&nama)
    .bind(&hash)
    .bind(role)
    .fetch_one(&pool)
    .await;

    let user = match row {
        Ok(u) => u,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(ApiError(StatusCode::CONFLICT, "Email sudah terdaftar.".into()))
        }
        Err(e) => return Err(e.into()),
    };

    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }))
}

#[derive(Deserialize)]
pub struct LoginReq {
    email: String,
    password: String,
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(req): Json<LoginReq>,
) -> Result<Json<AuthResp>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;

    let fail = || ApiError(StatusCode::UNAUTHORIZED, "Email atau kata sandi salah.".into());
    let user = user.ok_or_else(fail)?;
    if !verify_pw(req.password, user.password_hash.clone()).await {
        return Err(fail());
    }
    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }))
}

pub async fn me(Extension(user): Extension<DbUser>) -> Json<UserOut> {
    Json(user.into())
}

// ===================== PEMAKAIAN KREDIT =====================
// Aturan:
//  - Membuka provinsi / kabupaten / desa : cukup punya kredit > 0 (TIDAK dipotong).
//  - Ekspor PNG / PDF                    : kredit dipotong saat ekspor (lihat `cek_ekspor`).
//  - Admin                               : tidak dicek dan tidak dipotong.
fn cost_per_export() -> i32 {
    env::var("CREDIT_PER_EXPORT")
        .or_else(|_| env::var("CREDIT_PER_MAP")) // kompatibel dengan .env lama
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1)
}

fn kredit_habis() -> ApiError {
    ApiError(
        StatusCode::PAYMENT_REQUIRED,
        "Kredit Anda habis. Silakan top-up terlebih dahulu untuk mengakses peta.".into(),
    )
}

/// Gerbang akses: lolos jika admin atau kredit > 0. Tidak memotong kredit.
/// `user.kredit` selalu segar karena dibaca ulang dari DB oleh `require_auth` di setiap request.
fn cek_punya_kredit(user: &DbUser) -> Result<(), ApiError> {
    if user.role == "admin" || user.kredit > 0 {
        Ok(())
    } else {
        Err(kredit_habis())
    }
}

/// Dipanggil oleh handler get-desa (main.rs). Nama dipertahankan supaya main.rs tidak perlu diubah,
/// tetapi sekarang HANYA memeriksa kredit > 0 dan tidak memotong apa pun.
pub async fn charge_peta(_pool: &PgPool, user: &DbUser, _kabupaten: &str) -> Result<(), ApiError> {
    cek_punya_kredit(user)
}

// ===================== TOP-UP (USER) =====================
fn sniff_mime(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub async fn topup_create(
    State(pool): State<PgPool>,
    Extension(user): Extension<DbUser>,
    mut mp: Multipart,
) -> Result<Json<Value>, ApiError> {
    let mut nominal: i64 = 0;
    let mut catatan = String::new();
    let mut bukti: Option<Vec<u8>> = None;

    while let Some(field) = mp.next_field().await.map_err(|_| ApiError::bad("Form tidak valid atau file terlalu besar."))? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "nominal" => {
                let t = field.text().await.map_err(|_| ApiError::bad("Nominal tidak valid."))?;
                nominal = t.trim().parse().map_err(|_| ApiError::bad("Nominal harus berupa angka."))?;
            }
            "catatan" => {
                let t = field.text().await.map_err(|_| ApiError::bad("Catatan tidak valid."))?;
                catatan = t.chars().take(300).collect();
            }
            "bukti" => {
                let b = field.bytes().await.map_err(|_| ApiError::bad("Gagal membaca file bukti."))?;
                bukti = Some(b.to_vec());
            }
            _ => {}
        }
    }

    if nominal <= 0 || nominal > 100_000_000 {
        return Err(ApiError::bad("Nominal pembayaran tidak valid."));
    }
    let bukti = bukti.ok_or_else(|| ApiError::bad("Bukti pembayaran wajib diunggah."))?;
    if bukti.len() > 3 * 1024 * 1024 {
        return Err(ApiError::bad("Ukuran bukti maksimal 3 MB."));
    }
    let mime = sniff_mime(&bukti).ok_or_else(|| ApiError::bad("Bukti harus berupa gambar PNG, JPG, atau WEBP."))?;

    let (pending,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM topup_requests WHERE user_id = $1 AND status = 'pending'")
            .bind(user.id)
            .fetch_one(&pool)
            .await?;
    if pending >= 3 {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Masih ada 3 permintaan yang menunggu verifikasi admin.".into(),
        ));
    }

    sqlx::query(
        "INSERT INTO topup_requests (user_id, nominal, catatan, bukti, bukti_mime) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user.id)
    .bind(nominal)
    .bind(&catatan)
    .bind(&bukti)
    .bind(mime)
    .execute(&pool)
    .await?;

    Ok(Json(json!({ "success": true, "message": "Bukti terkirim. Admin akan memverifikasi dan menambahkan kredit Anda." })))
}

pub async fn topup_list_mine(
    State(pool): State<PgPool>,
    Extension(user): Extension<DbUser>,
) -> Result<Json<Vec<TopupOut>>, ApiError> {
    let q = format!("{TOPUP_SELECT} WHERE t.user_id = $1 ORDER BY t.id DESC LIMIT 20");
    let rows = sqlx::query_as::<_, TopupOut>(&q).bind(user.id).fetch_all(&pool).await?;
    Ok(Json(rows))
}

// ===================== ADMIN =====================
pub async fn admin_topup_list(
    State(pool): State<PgPool>,
    Extension(user): Extension<DbUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<TopupOut>>, ApiError> {
    require_admin(&user)?;
    let status = params.get("status").cloned().unwrap_or_else(|| "pending".into());
    let q = format!("{TOPUP_SELECT} WHERE ($1 = 'all' OR t.status = $1) ORDER BY t.id DESC LIMIT 100");
    let rows = sqlx::query_as::<_, TopupOut>(&q).bind(status).fetch_all(&pool).await?;
    Ok(Json(rows))
}

pub async fn admin_bukti(
    State(pool): State<PgPool>,
    Extension(user): Extension<DbUser>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let row: Option<(Vec<u8>, String)> =
        sqlx::query_as("SELECT bukti, bukti_mime FROM topup_requests WHERE id = $1")
            .bind(id)
            .fetch_optional(&pool)
            .await?;
    let (bytes, mime) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Bukti tidak ditemukan.".into()))?;
    Ok(([(header::CONTENT_TYPE, mime)], bytes).into_response())
}

#[derive(Deserialize)]
pub struct ApproveReq {
    kredit: i32,
}

pub async fn admin_approve(
    State(pool): State<PgPool>,
    Extension(admin): Extension<DbUser>,
    Path(id): Path<i64>,
    Json(req): Json<ApproveReq>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&admin)?;
    if req.kredit < 1 || req.kredit > 100_000 {
        return Err(ApiError::bad("Jumlah kredit harus 1 - 100.000."));
    }
    let mut tx = pool.begin().await?;
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT user_id FROM topup_requests WHERE id = $1 AND status = 'pending' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (uid,) = row.ok_or_else(|| ApiError(StatusCode::CONFLICT, "Permintaan tidak ditemukan atau sudah diproses.".into()))?;

    sqlx::query(
        "UPDATE topup_requests SET status = 'approved', kredit_diberikan = $1, reviewed_by = $2, reviewed_at = now() WHERE id = $3",
    )
    .bind(req.kredit)
    .bind(admin.id)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE users SET kredit = kredit + $1 WHERE id = $2")
        .bind(req.kredit)
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO kredit_log (user_id, delta, alasan, ref) VALUES ($1, $2, 'topup', $3)")
        .bind(uid)
        .bind(req.kredit)
        .bind(format!("topup#{id}"))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct RejectReq {
    alasan: Option<String>,
}

pub async fn admin_reject(
    State(pool): State<PgPool>,
    Extension(admin): Extension<DbUser>,
    Path(id): Path<i64>,
    Json(req): Json<RejectReq>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&admin)?;
    let alasan: String = req.alasan.unwrap_or_default().chars().take(200).collect();
    let r = sqlx::query(
        "UPDATE topup_requests SET status = 'rejected', alasan_admin = $1, reviewed_by = $2, reviewed_at = now()
         WHERE id = $3 AND status = 'pending'",
    )
    .bind(alasan)
    .bind(admin.id)
    .bind(id)
    .execute(&pool)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError(StatusCode::CONFLICT, "Permintaan tidak ditemukan atau sudah diproses.".into()));
    }
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct AddKreditReq {
    email: String,
    jumlah: i32,
    alasan: Option<String>,
}

/// Tambah/kurangi kredit manual berdasarkan email (tanpa bukti, mis. koreksi atau bonus).
pub async fn admin_add_kredit(
    State(pool): State<PgPool>,
    Extension(admin): Extension<DbUser>,
    Json(req): Json<AddKreditReq>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&admin)?;
    if req.jumlah == 0 || req.jumlah.abs() > 100_000 {
        return Err(ApiError::bad("Jumlah tidak valid."));
    }
    let mut tx = pool.begin().await?;
    let row: Option<(i64, i32)> = sqlx::query_as(
        "UPDATE users SET kredit = kredit + $1 WHERE email = $2 AND kredit + $1 >= 0 RETURNING id, kredit",
    )
    .bind(req.jumlah)
    .bind(req.email.trim().to_lowercase())
    .fetch_optional(&mut *tx)
    .await?;
    let (uid, saldo) = row.ok_or_else(|| ApiError::bad("User tidak ditemukan atau saldo akan menjadi negatif."))?;
    let alasan: String = req.alasan.unwrap_or_else(|| "manual".into()).chars().take(100).collect();
    sqlx::query("INSERT INTO kredit_log (user_id, delta, alasan, ref) VALUES ($1, $2, $3, $4)")
        .bind(uid)
        .bind(req.jumlah)
        .bind(alasan)
        .bind(format!("admin#{}", admin.id))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true, "saldo": saldo })))
}

#[derive(Deserialize)]
pub struct EksporReq {
    kabupaten: String,
}

/// Dipanggil tepat sebelum ekspor PNG/PDF. Di sinilah kredit dipotong (-1).
/// UPDATE bersyarat (kredit >= biaya) bersifat atomik, jadi request bersamaan tidak bisa
/// membuat saldo negatif maupun memotong dua kali untuk satu klik.
pub async fn cek_ekspor(
    State(pool): State<PgPool>,
    Extension(user): Extension<DbUser>,
    Json(req): Json<EksporReq>,
) -> Result<Json<Value>, ApiError> {
    if user.role == "admin" {
        return Ok(Json(json!({ "ok": true, "kredit": null })));
    }
    let biaya = cost_per_export();
    let mut tx = pool.begin().await?;

    let row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET kredit = kredit - $1 WHERE id = $2 AND kredit >= $1 RETURNING kredit",
    )
    .bind(biaya)
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let (sisa,) = row.ok_or_else(|| {
        ApiError(
            StatusCode::PAYMENT_REQUIRED,
            format!("Kredit tidak cukup. Ekspor membutuhkan {biaya} kredit, silakan top-up terlebih dahulu."),
        )
    })?;

    let ref_kab: String = req.kabupaten.chars().take(100).collect();
    sqlx::query("INSERT INTO kredit_log (user_id, delta, alasan, ref) VALUES ($1, $2, 'ekspor', $3)")
        .bind(user.id)
        .bind(-biaya)
        .bind(ref_kab)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "ok": true, "kredit": sisa })))
}
