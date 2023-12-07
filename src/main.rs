use std::env;

use anyhow::{anyhow, Ok, Result};
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier,
};
use lazy_static::lazy_static;
use rand_core::OsRng;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

pub const ARGON_SECRET: &'static [u8] = b"abcdef";
lazy_static! {
    static ref ARGON: Argon2<'static> = Argon2::new_with_secret(
        ARGON_SECRET,
        Algorithm::default(),
        argon2::Version::V0x13,
        Params::default()
    )
    .unwrap();
}
pub struct UserDb {
    pool: SqlitePool,
}
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
pub struct Users {
    id: i32,
    email: String,
    hashed_password: String,
}
impl UserDb {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn register(&self, email: &str, password: &str) -> Result<i64> {
        let hashed_pwd = hash_password(password)?;
        let id = sqlx::query("INSERT INTO users(email, hashed_password) values (?,?)")
            .bind(email)
            .bind(hashed_pwd)
            .execute(&self.pool)
            .await?
            .last_insert_rowid();
        Ok(id)
    }
    pub async fn login(&self, email: &str, password: &str) -> Result<String> {
        let user: Users = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&self.pool)
            .await?;
        if let Err(_) = verify_password(password, &user.hashed_password) {
            return Err(anyhow!("failed to login"));
        }
        Ok("aswsome token".to_owned())
    }
}

pub async fn recreate_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS users")
        .execute(pool)
        .await?;
    sqlx::query(
    r#"CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY NOT NULL, email VARCHAR UNIQUE NOT NULL, hashed_password VARCHAR NOT NULL)"#
    ).execute(pool).await?;
    Ok(())
}
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let pwd = ARGON
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            let e = e.to_string();
            anyhow!("failed to hash passwd error is {}", e)
        })?
        .to_string();
    Ok(pwd)
}

pub fn verify_password(password: &str, hashed_password: &str) -> Result<()> {
    let parsed_hash = PasswordHash::new(hashed_password).map_err(|e| {
        let e = e.to_string();
        anyhow!("failed to parse hased passwd {e:}")
    })?;
    ARGON
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| anyhow!("failed to verify password"))?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let url = env::var("DATABASE_URL").unwrap_or("sqlite://./data/example.db".to_string());
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;
    recreate_table(&pool).await?;
    let userdb = UserDb::new(pool.clone());
    let email = "zyzzz0928@gmail.com";
    let password = "poem42";

    let id = userdb.register(email, password).await;
    println!("register id {:?}", id);

    let token = userdb.login(email, password).await;
    println!("login scuess {:?}", token);

    let token2 = userdb.login(email, "err04").await;
    println!("login fail {:?}", token2);
    Ok(())
}
