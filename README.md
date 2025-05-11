# turn-rs

`turn-rs` is a Rust implementation of a TURN (Traversal Using Relays around NAT) server based on RFC 8656.

## Crates

This workspace contains the following crates:

*   `turn-proto`: Provides the core Sans-IO TURN/STUN protocol definitions, message parsing, and encoding/decoding logic.
*   `turn-service`: Implements the TURN server logic, including session management, allocation handling, and relaying endpoints.

## Implementations

An official implementation of this library can be found at `[turn-server](https:://github.com/dinesh/turn-server)`.
