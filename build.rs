use std::env;
use std::fs;
use std::path;
use std::process;

// Copies the files in src_dir to dst_dir.
// Only files are copied, not directories.
// dst_dir is created if it does not exist.
fn copy_headers_dir(src_dir: &path::PathBuf, dst_dir: &path::PathBuf) {
    fs::create_dir_all(&dst_dir).expect("Failed to create destination directory");
    for entry in fs::read_dir(src_dir).expect("Failed to read source directory") {
        let entry = entry.unwrap();
        let path = entry.path();
        // Skip directories for now
        if path.is_file() {
            fs::copy(&path, dst_dir.join(path.file_name().unwrap())).unwrap();
        }
    }
}

fn main() {
    let dst = path::PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let src_dir = path::PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let xdptools_dir = src_dir.join("xdp-tools");
    let libxdp_dir = xdptools_dir.join("lib/libxdp");
    let headers_dir = xdptools_dir.join("headers/xdp");

    let libbpf_dir = xdptools_dir.join("lib/libbpf/src");
    let bpf_headers_dir = libbpf_dir.join("root/include");

    let status = process::Command::new("make")
        .arg("libxdp")
        .current_dir(&xdptools_dir)
        .status()
        .expect("could not execute make");

    assert!(status.success(), "make libxdp failed");

    let status = process::Command::new("make")
        .current_dir(&libbpf_dir)
        .status()
        .expect("could not execute make");

    assert!(status.success(), "make libbpf failed");

    // Copy headers to the output directory
    let dst_header_dir = dst.join("include/xdp");
    copy_headers_dir(&headers_dir, &dst_header_dir);

    println!("cargo:include={}", dst_header_dir.display());
    println!("cargo:rustc-link-search={}", libxdp_dir.display());
    println!("cargo:rustc-link-search={}", libbpf_dir.display());
    println!("cargo:rustc-link-lib=static=xdp");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");

    bindgen::Builder::default()
        .header("bindings.h")
        .generate_inline_functions(true)
        .clang_arg(format!("-I{}", bpf_headers_dir.display()))
        .clang_arg(format!("-I{}", headers_dir.display()))
        .allowlist_var("BPF_.*")
        .allowlist_var("LIBBPF.*")
        .allowlist_var("XDP_.*")
        .allowlist_var("MAX_DISPATCHER_ACTIONS")
        .allowlist_var("XSK_.*")
        .allowlist_var("BTF_.*")
        .allowlist_function("xdp_.*")
        .allowlist_function("libxdp_.*")
        .allowlist_function("xsk_.*")
        .allowlist_function("btf_.*")
        .allowlist_function("bpf_.*")
        .allowlist_type("xsk_.*")
        .allowlist_type("xdp_.*")
        .allowlist_type("bpf_.*")
        .allowlist_type("btf_.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(src_dir.join("src/bindings.rs"))
        .expect("Couldn't write bindings");
}
