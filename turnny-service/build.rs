use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/isc/isc.proto"], &["src/"])?;
    Ok(())
}
