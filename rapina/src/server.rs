use std::net::SocketAddr;
use std::sync::Arc;

use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::context::RequestContext;
use crate::router::Router;
use crate::state::AppState;

pub async fn serve(router: Router, state: AppState, addr: SocketAddr) -> std::io::Result<()> {
    let router = Arc::new(router);
    let state = Arc::new(state);
    let listener = TcpListener::bind(addr).await?;

    println!("Rapina listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let router = router.clone();
        let state = state.clone();

        tokio::spawn(async move {
            let service = service_fn(move |mut req: Request<Incoming>| {
                let router = router.clone();
                let state = state.clone();

                // Create and inject RequestContext at request start
                let ctx = RequestContext::new();
                req.extensions_mut().insert(ctx);

                async move { Ok::<_, std::convert::Infallible>(router.handle(req, &state).await) }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("connection error: {}", e);
            }
        });
    }
}
