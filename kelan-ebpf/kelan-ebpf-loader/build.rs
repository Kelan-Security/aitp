

fn main() {
    #[cfg(target_os = "linux")]
    compile_ebpf_program();
}

#[cfg(target_os = "linux")]
fn compile_ebpf_program() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    let status = Command::new("cargo")
        .args([
            "build",
            "--package", "kelan-ebpf-program",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .current_dir("../kelan-ebpf-program")
        .env("CARGO_CFG_BPF", "1")
        .status()
        .expect("Failed to run cargo for eBPF program compilation");

    if !status.success() {
        panic!("eBPF program compilation failed.");
    }

    let bpf_obj = format!("../../target/bpfel-unknown-none/release/kelan_xdp");
    let dest = format!("{}/kelan_xdp.o", out_dir);

    std::fs::copy(&bpf_obj, &dest).expect("Failed to copy compiled eBPF object");

    println!("cargo:rerun-if-changed=../kelan-ebpf-program/src/main.rs");
    println!("cargo:rerun-if-changed=../kelan-ebpf-program/Cargo.toml");
}
