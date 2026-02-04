#[cfg(feature = "use_cc_build")]
use cc::Build;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

// Copies the files in src_dir to dst_dir.
// Only files are copied, not directories.
// dst_dir is created if it does not exist.
fn copy_headers_dir(src_dir: &Path, dst_dir: &Path) {
    fs::create_dir_all(dst_dir).expect("Failed to create destination directory");
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
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let src_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let xdptools_dir = src_dir.join("xdp-tools");
    let libxdp_dir = xdptools_dir.join("lib/libxdp");
    let libxdp_dir_str = libxdp_dir
        .to_str()
        .expect("Failed to convert libxdp_dir to string");
    let headers_dir = xdptools_dir.join("headers");
    let headers_xdp_dir = headers_dir.join("xdp");

    let bpf_headers_dir = std::env::var_os("DEP_BPF_INCLUDE")
        .map(PathBuf::from)
        .expect("Failed to get BPF include directory");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let obj_out_dir = out_dir.join("staticobjs");
    std::fs::create_dir_all(&obj_out_dir).expect("Failed to create output directory");
    std::fs::create_dir_all(obj_out_dir.join("bpf")).expect("Failed to create bpf directory");

    // Tell Cargo to rerun if any of these files change
    println!("cargo:rerun-if-changed={libxdp_dir_str}/libxdp.c");
    println!("cargo:rerun-if-changed={libxdp_dir_str}/xsk.c");
    println!("cargo:rerun-if-changed={libxdp_dir_str}/xdp-dispatcher.c");
    println!("cargo:rerun-if-changed={libxdp_dir_str}/xsk_def_xdp_prog.c");
    println!("cargo:rerun-if-changed={libxdp_dir_str}/xsk_def_xdp_prog_5.3.c");
    println!("cargo:rerun-if-changed={libxdp_dir_str}/libxdp.map");
    println!("cargo:rerun-if-changed=build.rs");

    compile_libxdp(
        &xdptools_dir,
        &libxdp_dir,
        &headers_dir,
        &bpf_headers_dir,
        &obj_out_dir,
    );

    // Copy headers to the output directory
    let dst_header_dir = dst.join("include/xdp");
    copy_headers_dir(&headers_dir, &dst_header_dir);

    println!("cargo:include={}", dst_header_dir.display());
    // Tell Cargo where to find the libraries
    println!("cargo:rustc-link-search=native={}", obj_out_dir.display());
    println!("cargo:rustc-link-lib=static=xdp");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");

    bindgen::Builder::default()
        .header("bindings.h")
        .generate_inline_functions(true)
        .clang_arg(format!("-I{}", bpf_headers_dir.display()))
        .clang_arg(format!("-I{}", headers_xdp_dir.display()))
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
        .write_to_file(src_dir.join(out_dir.join("bindings.rs")))
        .expect("Couldn't write bindings");
}

#[cfg(feature = "use_cc_build")]
fn compile_libxdp(
    _xdptools_dir: &Path,
    libxdp_dir: &Path,
    headers_dir: &Path,
    bpf_headers_dir: &Path,
    obj_out_dir: &Path,
) {
    // Compile C sources
    compile_c_sources(libxdp_dir, bpf_headers_dir, headers_dir, obj_out_dir);

    // Compile BPF programs
    compile_bpf_programs(libxdp_dir, bpf_headers_dir, headers_dir, obj_out_dir);

    // Create libraries
    create_libraries(obj_out_dir);
}

#[cfg(not(feature = "use_cc_build"))]
fn compile_libxdp(
    xdptools_dir: &Path,
    libxdp_dir: &Path,
    _headers_dir: &Path,
    _bpf_headers_dir: &Path,
    obj_out_dir: &Path,
) {
    let status = Command::new("make")
        .arg("libxdp")
        .current_dir(xdptools_dir)
        .status()
        .expect("could not execute make");

    assert!(status.success(), "make libxdp failed");
    // Copy the built library to the obj_out_dir directory
    fs::copy(libxdp_dir.join("libxdp.a"), obj_out_dir.join("libxdp.a"))
        .expect("Failed to copy libxdp.a");
}

#[cfg(feature = "use_cc_build")]
fn compile_c_sources(libxdp_dir: &Path, bpf_header: &Path, headers_dir: &Path, out_dir: &Path) {
    // Static builds
    let mut static_build = Build::new();
    configure_build(&mut static_build, true, bpf_header, headers_dir);
    static_build
        .file(libxdp_dir.join("libxdp.c"))
        .file(libxdp_dir.join("xsk.c"))
        .out_dir(out_dir)
        .compile("xdp_static");
}

#[cfg(feature = "use_cc_build")]
fn configure_build(build: &mut Build, is_static: bool, bpf_header: &Path, headers_dir: &Path) {
    let target_path = get_target_path();
    build
        .opt_level(2)
        .debug(true)
        .include(bpf_header)
        .include(headers_dir)
        .define("HAVE_ZLIB", None)
        .define("HAVE_ELF", None)
        .include("/usr/include/dbus-1.0")
        .include(format!("/usr/lib/{target_path}/dbus-1.0/include"))
        .include(format!("/usr/include/{target_path}"))
        .flag("-std=gnu11")
        .flag("-Wextra")
        .flag("-Werror")
        .define("BPF_DIR_MNT", "\"/sys/fs/bpf\"")
        .define("BPF_OBJECT_PATH", "\"/usr/local/lib/bpf\"")
        .define("MAX_DISPATCHER_ACTIONS", "10")
        .define("TOOLS_VERSION", "\"1.4.3\"")
        .define("LIBBPF_VERSION", "\"1.4.0\"")
        .define("RUNDIR", "\"/run\"")
        // HAVE_* macros
        .define("HAVE_LIBBPF_PERF_BUFFER__CONSUME", None)
        .define("HAVE_LIBBPF_BTF__LOAD_FROM_KERNEL_BY_ID", None)
        .define("HAVE_LIBBPF_BTF__TYPE_CNT", None)
        .define("HAVE_LIBBPF_BPF_OBJECT__NEXT_MAP", None)
        .define("HAVE_LIBBPF_BPF_OBJECT__NEXT_PROGRAM", None)
        .define("HAVE_LIBBPF_BPF_PROGRAM__INSN_CNT", None)
        .define("HAVE_LIBBPF_BPF_PROGRAM__TYPE", None)
        .define("HAVE_LIBBPF_BPF_PROGRAM__FLAGS", None)
        .define("HAVE_LIBBPF_BPF_PROGRAM__EXPECTED_ATTACH_TYPE", None)
        .define("HAVE_LIBBPF_BPF_MAP_CREATE", None)
        .define("HAVE_LIBBPF_PERF_BUFFER__NEW_RAW", None)
        .define("HAVE_LIBBPF_BPF_XDP_ATTACH", None)
        .define("HAVE_LIBBPF_BPF_MAP__SET_AUTOCREATE", None)
        .define("HAVE_LIBBPF_BPF_PROG_TEST_RUN_OPTS", None)
        .define("HAVE_LIBBPF_BPF_XDP_QUERY", None)
        .define("HAVE_SECURE_GETENV", None)
        .define("DEBUG", None)
        .define("_LARGEFILE64_SOURCE", None)
        .define("_FILE_OFFSET_BITS", "64")
        .flag("-Wall");

    if is_static {
        build.define("LIBXDP_STATIC", "1");
    } else {
        build.define("SHARED", None);
    }
}

#[cfg(feature = "use_cc_build")]
fn get_target_path() -> String {
    let target = env::var("TARGET").expect("Could not read TARGET environment variable");
    if target.starts_with("aarch64") {
        return "aarch64-linux-gnu".to_string();
    } else if target == "arm-unknown-linux-gnueabihf" || target == "armv7-unknown-linux-gnueabihf" {
        return "arm-linux-gnueabihf".to_string();
    } else if target.starts_with("x86_64") {
        return "x86_64-linux-gnu".to_string();
    } else if target.starts_with("i686") {
        return "i386-linux-gnu".to_string();
    } else if target.starts_with("riscv64") {
        return "riscv64-linux-gnu".to_string();
    } else if target.starts_with("powerpc64") {
        return "powerpc64-linux-gnu".to_string();
    } else if target.starts_with("s390x") {
        return "s390x-linux-gnu".to_string();
    }
    panic!("Unsupported target: {target}");
}

#[cfg(feature = "use_cc_build")]
fn compile_bpf_programs(
    libxdp_dir: &Path,
    bpf_headers_dir: &Path,
    headers_dir: &Path,
    out_dir: &Path,
) {
    let xdp_dispatcher_dest = out_dir.join("xdp-dispatcher.c");
    #[cfg(not(feature = "use_precompiled_bpf"))]
    {
        // Translate xdp-dispatcher.c.in with m4
        let m4_cmd = std::env::var("M4").unwrap_or_else(|_| "m4".to_string());
        let xdp_dispatcher_src = libxdp_dir.join("xdp-dispatcher.c.in");
        let status = Command::new(m4_cmd)
            .arg(xdp_dispatcher_src)
            .arg("-o")
            .arg(&xdp_dispatcher_dest)
            .status()
            .expect("Failed to execute m4");
        assert!(status.success(), "Failed to preprocess xdp-dispatcher.c.in");
    }

    // Compile each BPF program
    compile_bpf_program(&xdp_dispatcher_dest, bpf_headers_dir, headers_dir, out_dir);
    compile_bpf_program(
        &libxdp_dir.join("xsk_def_xdp_prog.c"),
        bpf_headers_dir,
        headers_dir,
        out_dir,
    );
    compile_bpf_program(
        &libxdp_dir.join("xsk_def_xdp_prog_5.3.c"),
        bpf_headers_dir,
        headers_dir,
        out_dir,
    );
}

#[cfg(not(feature = "use_precompiled_bpf"))]
#[cfg(not(feature = "use_cc_build"))]
fn compile_bpf_program(
    src_file: &Path,
    _bpf_headers_dir: &Path,
    _headers_dir: &Path,
    out_dir: &Path,
) {
    let base_name = src_file.file_stem().unwrap().to_str().unwrap();
    let bpf_dir = out_dir.join("bpf");
    std::fs::create_dir_all(&bpf_dir).expect("Failed to create bpf directory");
    let obj_file_str = format!("{base_name}.o");
    let embed_obj_file_str = format!("{base_name}.embed.o");
    let src_folder = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("prebuilt_ebpf");
    std::fs::copy(src_folder.join(&obj_file_str), bpf_dir.join(&obj_file_str))
        .expect("Failed to copy object file");
    create_embed_obj(out_dir, &bpf_dir, &obj_file_str, &embed_obj_file_str);
}

#[cfg(feature = "use_cc_build")]
fn compile_bpf_program(
    src_file: &Path,
    bpf_headers_dir: &Path,
    headers_dir: &Path,
    out_dir: &Path,
) {
    let target_path = get_target_path();
    let target_include = format!("-I/usr/include/{target_path}");
    let flags = [
        "-S",
        "-target",
        "bpf",
        "-D",
        "__BPF_TRACING__",
        "-Wno-visibility",
        "-fno-stack-protector",
        "-I",
        bpf_headers_dir.to_str().unwrap(),
        target_include.as_str(),
        "-DBPF_DIR_MNT=\"/sys/fs/bpf\"",
        "-DBPF_OBJECT_PATH=\"/usr/local/lib/bpf\"",
        "-DMAX_DISPATCHER_ACTIONS=10",
        "-DTOOLS_VERSION=\"\"1.4.3\"\"",
        "-DLIBBPF_VERSION=\"1.4.0\"",
        "-DRUNDIR=\"/run\"",
        "-DHAVE_LIBBPF_PERF_BUFFER__CONSUME",
        "-DHAVE_LIBBPF_BTF__LOAD_FROM_KERNEL_BY_ID",
        "-DHAVE_LIBBPF_BTF__TYPE_CNT",
        "-DHAVE_LIBBPF_BPF_OBJECT__NEXT_MAP",
        "-DHAVE_LIBBPF_BPF_OBJECT__NEXT_PROGRAM",
        "-DHAVE_LIBBPF_BPF_PROGRAM__INSN_CNT",
        "-DHAVE_LIBBPF_BPF_PROGRAM__TYPE",
        "-DHAVE_LIBBPF_BPF_PROGRAM__FLAGS",
        "-DHAVE_LIBBPF_BPF_PROGRAM__EXPECTED_ATTACH_TYPE",
        "-DHAVE_LIBBPF_BPF_MAP_CREATE",
        "-DHAVE_LIBBPF_PERF_BUFFER__NEW_RAW",
        "-DHAVE_LIBBPF_BPF_XDP_ATTACH",
        "-DHAVE_LIBBPF_BPF_MAP__SET_AUTOCREATE",
        "-DHAVE_LIBBPF_BPF_PROG_TEST_RUN_OPTS",
        "-DHAVE_LIBBPF_BPF_XDP_QUERY",
        "-DHAVE_SECURE_GETENV",
        "-DDEBUG",
        "-D_LARGEFILE64_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-I",
        headers_dir.to_str().unwrap(),
        "-Wall",
        "-Wno-unused-value",
        "-Wno-pointer-sign",
        "-Wno-compare-distinct-pointer-types",
        "-Werror",
        "-O2",
        "-emit-llvm",
        "-c",
        "-g",
    ];
    let base_name = src_file.file_stem().unwrap().to_str().unwrap();
    let bpf_dir = out_dir.join("bpf");
    std::fs::create_dir_all(&bpf_dir).expect("Failed to create bpf directory");
    let ll_file_str = format!("{base_name}.ll");
    let obj_file_str = format!("{base_name}.o");
    let embed_obj_file_str = format!("{base_name}.embed.o");

    // Step 1: Compile to LLVM IR with clang
    let clang_cmd = std::env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let status = Command::new(clang_cmd)
        .current_dir(&bpf_dir)
        .args(flags)
        .arg("-o")
        .arg(&ll_file_str)
        .arg(src_file)
        .status()
        .expect("Failed to execute clang");
    assert!(
        status.success(),
        "Failed to compile {} to LLVM IR",
        src_file.to_str().unwrap()
    );

    // Step 2: Convert to BPF object
    let llc_cmd = find_llc_command();
    let status = Command::new(llc_cmd)
        .current_dir(&bpf_dir)
        .args([
            "-march=bpf",
            "-filetype=obj",
            "-o",
            &obj_file_str,
            &ll_file_str,
        ])
        .status()
        .expect("Failed to execute llc");
    assert!(
        status.success(),
        "Failed to convert {ll_file_str} to object"
    );

    create_embed_obj(out_dir, &bpf_dir, &obj_file_str, &embed_obj_file_str);
}

fn create_embed_obj(out_dir: &Path, bpf_dir: &Path, obj_file_str: &str, embed_obj_file_str: &str) {
    // Step 3: Create binary embed object
    let ld_cmd = std::env::var("LD").unwrap_or_else(|_| "ld".to_string());
    let status = Command::new(ld_cmd)
        .current_dir(bpf_dir)
        .args([
            "-r",
            "-b",
            "binary",
            "-o",
            embed_obj_file_str,
            "-z",
            "noexecstack",
            "--format=binary",
            obj_file_str,
        ])
        .status()
        .expect("Failed to execute ld");
    assert!(status.success(), "Failed to create embed object");

    // Step 4: Rename section
    let objcopy_cmd = std::env::var("OBJCOPY").unwrap_or_else(|_| "objcopy".to_string());
    let status = Command::new(objcopy_cmd)
        .current_dir(bpf_dir)
        .args([
            "--rename-section",
            ".data=.rodata,alloc,load,readonly,data,contents",
            embed_obj_file_str,
            out_dir.join(embed_obj_file_str).to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute objcopy");
    assert!(status.success(), "Failed to rename section");
}

#[cfg(feature = "use_cc_build")]
fn find_llc_command() -> String {
    let llc_candidate = std::env::var("LLC").unwrap_or_else(|_| "llc".to_string());
    if Command::new(&llc_candidate)
        .arg("--version")
        .output()
        .is_ok()
    {
        return llc_candidate;
    }
    let clang_name = std::env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let clang_path = PathBuf::from(clang_name);
    let clang_name = clang_path.file_name().unwrap().to_str().unwrap();
    let paths = env::var("PATH").unwrap_or_default();
    for path in env::split_paths(&paths) {
        let llc_path = path.join(&llc_candidate);
        if llc_path.exists() && llc_path.is_file() {
            return llc_path.to_str().unwrap().to_string();
        }
        let clang_path = path.join(clang_name);
        if clang_path.exists() && clang_path.is_file() {
            // Read link and get parent directory
            if let Ok(link_target) = clang_path.canonicalize() {
                if let Some(parent) = link_target.parent() {
                    for entry in std::fs::read_dir(parent).unwrap().flatten() {
                        if entry.file_name().to_str().unwrap().starts_with("llc") {
                            return entry.path().to_str().unwrap().to_string();
                        }
                    }
                }
            }
        }
    }
    panic!("Could not find llc command in PATH");
}

#[cfg(feature = "use_cc_build")]
fn create_libraries(out_dir: &Path) {
    // Create static library
    let obj_files = out_dir
        .read_dir()
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "o"))
        .map(|e| e.file_name())
        .collect::<Vec<_>>();
    let ar_cmd = std::env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let status = Command::new(ar_cmd)
        .current_dir(out_dir)
        .args(["rcs", out_dir.join("libxdp.a").to_str().unwrap()])
        .args(obj_files)
        .status()
        .expect("Failed to execute ar");
    assert!(status.success(), "Failed to create static library");
}
