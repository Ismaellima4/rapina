use rapina::prelude::*;

#[get("/")]
async fn hello() -> &'static str {
    "Hello, Rapina!"
}

#[get("/health")]
async fn health() -> StatusCode {
    StatusCode::OK
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let router = Router::new().get("/", hello).get("/health", health);

    Rapina::new().router(router).listen("127.0.0.1:3000").await
}
