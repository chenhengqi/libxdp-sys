use std::env;
use std::path;
use std::process;

fn main() {
    let src_dir = path::PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let xdptools_dir = src_dir.join("xdp-tools");
    let libxdp_dir = xdptools_dir.join("lib/libxdp");
    let headers_dir = xdptools_dir.join("headers/xdp");

    let libbpf_dir = xdptools_dir.join("lib/libbpf/src");
    let bpf_headers_dir = libbpf_dir.join("root/usr/include");

    let status = process::Command::new("make")
        .arg("libxdp")
        .current_dir(&xdptools_dir)
        .status()
        .expect("could not execute make");

    assert!(status.success(), "make failed");

    println!("cargo:rustc-link-search={}", libbpf_dir.display());
    println!("cargo:rustc-link-search={}", libxdp_dir.display());
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=xdp");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");

    bindgen::Builder::default()
        .header("bindings.h")
        .generate_inline_functions(true)
        .clang_arg(format!("-I{}", bpf_headers_dir.display()))
        .clang_arg(format!("-I{}", headers_dir.display()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(src_dir.join("src/bindings.rs"))
        .expect("Couldn't write bindings");
}
