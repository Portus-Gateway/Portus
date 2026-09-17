fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = format!("{}/../../proto", manifest_dir);
    let proto_files = [
        format!("{}/portus/v1/config.proto", proto_dir),
        format!("{}/portus/v1/ledger.proto", proto_dir),
    ];
    for f in &proto_files {
        println!("cargo:rerun-if-changed={}", f);
    }
    println!("cargo:rerun-if-changed=build.rs");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, &[proto_dir])?;
    Ok(())
}
