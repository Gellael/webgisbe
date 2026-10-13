use argon2::{
    password_hash::{rand_core::{OsRng, RngCore}, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
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
use sha2::{Digest, Sha256};
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

-- Verifikasi email. User yang sudah ada saat kolom ini pertama kali ditambahkan dianggap terverifikasi
-- (kolom ditambah dengan DEFAULT true, lalu default diganti false untuk pendaftar baru).
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT false;

CREATE TABLE IF NOT EXISTS email_verifications (
    user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_hash    TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
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

// ===================== REGISTER / LOGIN / VERIFIKASI EMAIL =====================
const CODE_TTL_MIN: i32 = 15; // masa berlaku kode (menit)
const RESEND_COOLDOWN_SEC: f64 = 60.0; // jeda minimal antar pengiriman kode
const MAX_ATTEMPTS: i32 = 5; // salah input maksimal per kode

/// Kode disimpan sebagai hash (bukan teks asli), diikat ke user_id + JWT_SECRET.
fn hash_code(user_id: i64, code: &str) -> String {
    let input = format!("{user_id}:{code}:{}", jwt_secret());
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// Kirim kode via SMTP. Env: SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM (opsional), SMTP_PORT (opsional, default 587).
/// Escape karakter HTML supaya nama user tidak bisa menyisipkan tag ke email.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const EMAIL_HTML: &str = r##"<!DOCTYPE html>
<html lang="id">
<body style="margin:0;padding:0;background-color:#f1f5f9;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f5f9">
<tr><td align="center" style="padding:32px 12px;">

  <table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:480px;background-color:#ffffff;border-radius:16px;overflow:hidden;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">

    <!-- Header -->
    <tr><td align="center" bgcolor="#0f172a" style="background-color:#0f172a;padding:28px 24px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td align="center" valign="middle" width="48" height="48" bgcolor="#facc15" style="background-color:#facc15;border-radius:12px;width:48px;height:48px;font-size:28px;line-height:48px;text-align:center;">&#9889;</td>
        <td valign="middle" style="padding-left:12px;font-size:28px;font-weight:800;letter-spacing:0.5px;color:#ffffff;">Peta<span style="color:#facc15;">kilat</span></td>
      </tr></table>
      <div style="margin-top:8px;font-size:13px;color:#94a3b8;">Peta cepat, data tepat</div>
    </td></tr>

    <!-- Isi -->
    <tr><td style="padding:32px 28px 8px 28px;color:#0f172a;">
      <div style="font-size:20px;font-weight:700;margin-bottom:12px;">Halo, {{NAMA}} &#128075;</div>
      <div style="font-size:15px;line-height:1.6;color:#334155;">
        Terima kasih sudah mendaftar di Petakilat. Masukkan kode berikut untuk memverifikasi email Anda:
      </div>
    </td></tr>

    <!-- Kode -->
    <tr><td align="center" style="padding:20px 28px;">
      <div style="display:inline-block;background-color:#fffbeb;border:2px dashed #facc15;border-radius:12px;padding:16px 28px;font-family:'Courier New',Consolas,monospace;font-size:36px;font-weight:800;letter-spacing:10px;color:#0f172a;">{{KODE}}</div>
    </td></tr>

    <tr><td style="padding:0 28px 28px 28px;">
      <div style="font-size:14px;line-height:1.6;color:#64748b;text-align:center;">
        Kode berlaku <strong style="color:#0f172a;">{{TTL}} menit</strong>.<br>
        Demi keamanan, jangan bagikan kode ini kepada siapa pun.
      </div>
    </td></tr>

    <!-- Footer -->
    <tr><td bgcolor="#f8fafc" style="background-color:#f8fafc;padding:18px 28px;border-top:1px solid #e2e8f0;">
      <div style="font-size:12px;line-height:1.6;color:#94a3b8;text-align:center;">
        Tidak merasa mendaftar di Petakilat? Abaikan saja email ini.<br>
        &copy; Petakilat &#9889;
      </div>
    </td></tr>

  </table>

</td></tr>
</table>
</body>
</html>"##;

/// Kirim kode via SMTP. Env: SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM (opsional), SMTP_PORT (opsional, default 587).
async fn send_code_email(to: &str, nama: &str, code: &str) -> Result<(), String> {
    use lettre::{
        message::{Mailbox, MultiPart},
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };
    let host = env::var("SMTP_HOST").map_err(|_| "SMTP_HOST belum diset".to_string())?;
    let user = env::var("SMTP_USER").map_err(|_| "SMTP_USER belum diset".to_string())?;
    let pass = env::var("SMTP_PASS").map_err(|_| "SMTP_PASS belum diset".to_string())?;
    let from = env::var("SMTP_FROM").unwrap_or_else(|_| user.clone());
    let port: u16 = env::var("SMTP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(587);

    let plain = format!(
        "Halo {nama},\n\nKode verifikasi email Anda di Petakilat: {code}\n\n\
         Kode berlaku {CODE_TTL_MIN} menit. Jangan bagikan kode ini kepada siapa pun.\n\
         Jika Anda tidak merasa mendaftar di Petakilat, abaikan email ini.\n"
    );
    let html = EMAIL_HTML
        .replace("{{NAMA}}", &html_escape(nama))
        .replace("{{KODE}}", code)
        .replace("{{TTL}}", &CODE_TTL_MIN.to_string());

    let msg = Message::builder()
        .from(from.parse::<Mailbox>().map_err(|e| e.to_string())?)
        .to(to.parse::<Mailbox>().map_err(|e| e.to_string())?)
        .subject(format!("⚡ {code} adalah kode verifikasi Petakilat Anda"))
        .multipart(MultiPart::alternative_plain_html(plain, html))
        .map_err(|e| e.to_string())?;

    let relay = if port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
    };
    let mailer = relay
        .map_err(|e| e.to_string())?
        .port(port)
        .credentials(Credentials::new(user, pass))
        .build();
    mailer.send(msg).await.map(|_| ()).map_err(|e| e.to_string())
}

/// Buat kode baru lalu kirim ke email. Ditolak (429) jika masih dalam masa jeda.
async fn issue_code(pool: &PgPool, user: &DbUser) -> Result<(), ApiError> {
    let code = format!("{:06}", OsRng.next_u32() % 1_000_000);
    let r = sqlx::query(
        "INSERT INTO email_verifications (user_id, code_hash, expires_at, attempts, last_sent_at)
         VALUES ($1, $2, now() + make_interval(mins => $3), 0, now())
         ON CONFLICT (user_id) DO UPDATE
           SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at,
               attempts = 0, last_sent_at = now()
           WHERE email_verifications.last_sent_at < now() - make_interval(secs => $4)",
    )
    .bind(user.id)
    .bind(hash_code(user.id, &code))
    .bind(CODE_TTL_MIN)
    .bind(RESEND_COOLDOWN_SEC)
    .execute(pool)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Tunggu sekitar 1 menit sebelum meminta kode baru.".into(),
        ));
    }
    send_code_email(&user.email, &user.nama, &code).await.map_err(|e| {
        eprintln!("Gagal kirim email verifikasi ke {}: {e}", user.email);
        ApiError(StatusCode::BAD_GATEWAY, "Gagal mengirim email verifikasi. Coba lagi nanti.".into())
    })
}

#[derive(Deserialize)]
pub struct RegisterReq {
    email: String,
    nama: String,
    password: String,
}

/// Mendaftar TIDAK langsung memberi token. User harus verifikasi email dulu.
pub async fn register(
    State(pool): State<PgPool>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<Value>, ApiError> {
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
    // Email di ADMIN_EMAIL otomatis menjadi admin (tetap harus verifikasi email dulu sebelum bisa masuk)
    let is_admin = env::var("ADMIN_EMAIL")
        .map(|a| a.trim().to_lowercase() == email)
        .unwrap_or(false);
    let role = if is_admin { "admin" } else { "user" };

    // Email yang sudah terdaftar tapi BELUM terverifikasi boleh mendaftar ulang (data ditimpa),
    // supaya email tidak "terkunci" oleh pendaftaran yang tidak pernah diselesaikan.
    let user: Option<DbUser> = sqlx::query_as(
        "INSERT INTO users (email, nama, password_hash, role) VALUES ($1, $2, $3, $4)
         ON CONFLICT (email) DO UPDATE SET nama = EXCLUDED.nama, password_hash = EXCLUDED.password_hash
         WHERE users.email_verified = false
         RETURNING id, email, nama, password_hash, role, kredit",
    )
    .bind(&email)
    .bind(&nama)
    .bind(&hash)
    .bind(role)
    .fetch_optional(&pool)
    .await?;
    let user = user.ok_or_else(|| ApiError(StatusCode::CONFLICT, "Email sudah terdaftar.".into()))?;

    issue_code(&pool, &user).await?;
    Ok(Json(json!({ "needs_verification": true, "email": user.email })))
}

#[derive(Deserialize)]
pub struct LoginReq {
    email: String,
    password: String,
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(req): Json<LoginReq>,
) -> Result<Response, ApiError> {
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

    let (verified,): (bool,) = sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&pool)
        .await?;
    if !verified {
        // Kirim kode baru (diabaikan kalau masih masa jeda: kode sebelumnya masih berlaku)
        let _ = issue_code(&pool, &user).await;
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Email belum diverifikasi. Masukkan kode yang dikirim ke email Anda.",
                "code": "email_not_verified",
                "email": user.email
            })),
        )
            .into_response());
    }
    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }).into_response())
}

#[derive(Deserialize)]
pub struct VerifyReq {
    email: String,
    code: String,
}

pub async fn verify_email(
    State(pool): State<PgPool>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<AuthResp>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let bad = || ApiError::bad("Kode salah.");
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;
    let user = user.ok_or_else(bad)?;

    // Setiap percobaan dihitung secara atomik; kode mati setelah MAX_ATTEMPTS salah atau kedaluwarsa.
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE email_verifications SET attempts = attempts + 1
         WHERE user_id = $1 AND attempts < $2 AND expires_at > now()
         RETURNING code_hash",
    )
    .bind(user.id)
    .bind(MAX_ATTEMPTS)
    .fetch_optional(&pool)
    .await?;
    let (stored,) = row.ok_or_else(|| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Kode kedaluwarsa atau terlalu banyak percobaan. Minta kode baru.".into(),
        )
    })?;
    if stored != hash_code(user.id, req.code.trim()) {
        return Err(bad());
    }

    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }))
}

#[derive(Deserialize)]
pub struct ResendReq {
    email: String,
}

/// Jawaban selalu sama agar endpoint ini tidak bisa dipakai menebak email yang terdaftar.
pub async fn resend_code(
    State(pool): State<PgPool>,
    Json(req): Json<ResendReq>,
) -> Result<Json<Value>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1 AND email_verified = false",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;
    if let Some(u) = user {
        issue_code(&pool, &u).await?;
    }
    Ok(Json(json!({ "success": true })))
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