# NOTE : This project is under heavy development. The API and the structure of the code may change rapidly.

# turnny-rs

`turnny-rs` is a Rust implementation of a TURN (Traversal Using Relays around NAT) server based on RFC 8656.

## Crates

This workspace contains the following crates:

*   `turnny-proto`: Provides the core Sans-IO TURN/STUN protocol definitions, message parsing, and encoding/decoding logic.
*   `turnny-service`: Implements the TURN server logic, including session management, allocation handling, and relaying endpoints.
*   `turnny` : Official implementaion of the TURN protocol using the crates above.
