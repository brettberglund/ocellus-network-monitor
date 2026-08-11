fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("proto");
    let proto_file = proto_dir.join("monitor.proto");

    let fds = protox::compile([&proto_file], [&proto_dir])?;

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_fds(fds)?;

    println!("cargo:rerun-if-changed={}", proto_file.display());
    Ok(())
}
