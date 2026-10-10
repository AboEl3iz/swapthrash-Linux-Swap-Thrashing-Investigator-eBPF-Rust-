use std::process::Command;

const SRC: &str = "src/bpf/swapthrash.bpf.c";
const OUT: &str = "src/bpf/swapthrash.bpf.o";

fn main() {
    let status = Command::new("clang")
        .args([
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-Isrc/bpf",
            "-I/usr/include/bpf",
            "-c",
            SRC,
            "-o",
            OUT,
        ])
        .status()
        .expect("Failed to execute clang to compile eBPF code");

    if !status.success() {
        panic!("clang failed to compile BPF code with exit code {:?}", status.code());
    }

    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed=src/bpf/swapthrash.h");
}
