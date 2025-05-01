use rand::Rng;
use std::sync::Mutex;
use turn_proto::wire::error::TurnErrorCode;

pub trait PortAllocator: Sync + Send + 'static {
    fn allocate_port(&self, username: &str) -> Result<u16, TurnErrorCode>;
    fn surrender_port(&self, username: &str, port: u16);
}

pub struct RandomPortAllocator {
    inner: Mutex<Vec<u16>>,
}

impl RandomPortAllocator {
    pub fn new() -> Self {
        RandomPortAllocator {
            inner: Mutex::new((10000..50000).collect()),
        }
    }
}

impl PortAllocator for RandomPortAllocator {
    fn allocate_port(&self, _: &str) -> Result<u16, TurnErrorCode> {
        let mut guard = self.inner.lock().unwrap();
        let index = match guard.len() {
            0 => return Err(TurnErrorCode::InsufficientCapacity),
            len => rand::rng().random_range(0..len),
        };
        Ok(guard.swap_remove(index))
    }

    fn surrender_port(&self, _: &str, port: u16) {
        let mut guard = self.inner.lock().unwrap();
        guard.push(port);
    }
}
