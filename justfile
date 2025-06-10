run config="./turnserver.conf" :
    RUST_LOG=INFO RUST_BACKTRACE=true cargo run -- --config {{config}}
    
trace config="./turnserver.conf" :
    RUST_LOG=TRACE RUST_BACKTRACE=true cargo run -- --config {{config}}
