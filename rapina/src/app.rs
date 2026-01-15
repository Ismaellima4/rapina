use std::net::SocketAddr;

use crate::router::Router;
use crate::server::serve;

pub struct Rapina {
    router: Router,
}

impl Rapina {
    pub fn new() -> Self {
        Self {
            router: Router::new(),
        }
    }

    pub fn router(mut self, router: Router) -> Self {
        self.router = router;
        self
    }

    pub async fn listen(self, addr: &str) -> std::io::Result<()> {
        let addr: SocketAddr = addr.parse().expect("invalid address");
        serve(self.router, addr).await
    }
}

impl Default for Rapina {
    fn default() -> Self {
        Self::new()
    }
}
