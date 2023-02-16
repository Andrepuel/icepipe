use crate::error::TimeoutError;
use std::time::{Duration, Instant};
use tokio::{select, time::sleep_until};

pub struct Ping {
    last_ping: Instant,
    last_pong: Instant,
}
impl Ping {
    pub fn new() -> Ping {
        Ping {
            last_ping: Instant::now(),
            last_pong: Instant::now(),
        }
    }

    pub async fn wait(&self) -> Result<MustPing, TimeoutError> {
        let next_ping = self.last_ping + Duration::from_secs(15);
        let pong_timeout = self.last_pong + Duration::from_secs(60);

        select! {
            _ = sleep_until(next_ping.into()) => {
                Ok(MustPing)
            }
            _ = sleep_until(pong_timeout.into()) => {
                Err(TimeoutError)
            }
        }
    }

    pub fn sent_ping(&mut self) {
        self.last_ping = Instant::now();
    }

    pub fn received_pong(&mut self) {
        self.last_ping = Instant::now();
        self.last_pong = Instant::now();
    }
}

impl Default for Ping {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MustPing;
