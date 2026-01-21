use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub trace_id: String,
    pub start_time: Instant,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            trace_id: uuid::Uuid::new_v4().to_string(),
            start_time: Instant::now(),
        }
    }

    pub fn with_trace_id(trace_id: String) -> Self {
        Self {
            trace_id,
            start_time: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}
