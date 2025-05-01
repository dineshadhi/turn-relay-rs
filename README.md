# turn-rs

`turn-rs` is a Rust implementation of a TURN (Traversal Using Relays around NAT) server based on RFC 8656.

## Crates

This workspace contains the following crates:

*   `turn-proto`: Provides the core Sans-IO TURN/STUN protocol definitions, message parsing, and encoding/decoding logic.
*   `turn-service`: Implements the TURN server logic, including session management, allocation handling, and relaying endpoints.

## Usage

An example TURN server can be found in `turn-service/examples/server.rs`. You can run it using:

```bash
cargo run --example server -- --help # To see options
# Example command to run the server (adjust parameters as needed):
# cargo run --example server -- --public-ip 127.0.0.1 --realm your_realm --port 3478
```
