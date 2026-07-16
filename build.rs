use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=bpfx-ebpf/src");
    println!("cargo:rerun-if-changed=bpfx-ebpf/Cargo.toml");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let status = Command::new("cargo")
        .current_dir(&manifest_dir)
        .env("RUSTFLAGS", "-Awarnings")
        .args([
            "+nightly",
            "build",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "--release",
            "--manifest-path",
        ])
        .arg(manifest_dir.join("bpfx-ebpf/Cargo.toml"))
        .status()
        .expect("failed to build eBPF program");

    assert!(status.success(), "eBPF build failed");

    let ebpf = manifest_dir.join("target/bpfel-unknown-none/release/bpfx-ebpf");

    println!("cargo:rustc-env=BPFX_EBPF={}", ebpf.display());
}
