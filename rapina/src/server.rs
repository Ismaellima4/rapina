use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::router::Router;

pub async fn serve(router: Router, addr: SocketAddr) -> std::io::Result<()> {
    let router = Arc::new(router);
    let listener = TcpListener::bind(addr).await?;

    println!("Rapina listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let router = router.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let router = router.clone();
                async move { Ok::<_, std::convert::Infallible>(router.handle(req).await) }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("connection error: {}", e);
            }
        });
    }
}
