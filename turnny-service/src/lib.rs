pub mod config;
pub mod endpoint;
pub mod instance;
pub mod portallocator;
pub mod session;

pub use turn_proto::config::*;
pub use turn_proto::wire::*;

#[macro_export]
macro_rules! session_counter {
    ($val:expr, $protocol:expr, $addr:expr) => {
        let session_counter = global::meter("turn-service")
            .i64_up_down_counter("turn.active-sessions")
            .with_description("Total Sessions")
            .build();

        session_counter.add(
            $val,
            &[
                KeyValue::new("protocol", format!("{:?}", $protocol)),
                KeyValue::new("remote_addr", $addr.to_string()),
            ],
        );
    };
}
