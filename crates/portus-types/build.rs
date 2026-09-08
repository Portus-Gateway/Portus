fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = format!("{}/../../proto", manifest_dir);
    let proto_file = format!("{}/portus/v1/config.proto", proto_dir);
    println!("cargo:rerun-if-changed={}", proto_file);
    println!("cargo:rerun-if-changed=build.rs");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(std::slice::from_ref(&proto_file), &[proto_dir])?;
    Ok(())
}
