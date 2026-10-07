fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = format!("{}/../../proto", manifest_dir);
    let proto_files = [
        format!("{}/portus/v1/config.proto", proto_dir),
        format!("{}/portus/v1/ledger.proto", proto_dir),
    ];
    // OTLP trace export (vendored opentelemetry-proto). The server half is
    // only used by the exporter's tests, as a fake collector.
    let otlp_files = [format!("{}/opentelemetry/proto/collector/trace/v1/trace_service.proto", proto_dir)];
    for f in proto_files.iter().chain(&otlp_files) {
        println!("cargo:rerun-if-changed={}", f);
    }
    println!("cargo:rerun-if-changed={}/opentelemetry", proto_dir);
    println!("cargo:rerun-if-changed=build.rs");
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_files, std::slice::from_ref(&proto_dir))?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&otlp_files, &[proto_dir])?;
    Ok(())
}
