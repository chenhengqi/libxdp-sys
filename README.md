# libxdp-sys

Rust FFI bindings for the [libxdp](https://github.com/xdp-project/xdp-tools/tree/main/lib/libxdp) C library, enabling safe and efficient interaction with XDP (eXpress Data Path) features from Rust.

## Overview

`libxdp-sys` provides low-level, auto-generated Rust bindings to the libxdp C library. These bindings allow Rust programs to interact with XDP objects, manage XDP programs, and utilize advanced networking features exposed by libxdp.

This crate is intended for use as a building block for higher-level Rust libraries and applications that require direct access to XDP functionality. It is not a high-level API; instead, it exposes the raw C interface as closely as possible.

## Features
- Bindings to libxdp and related XDP/BPF types and functions
- Optional vendored build of libbpf via the `vendored` feature
- Compatible with modern Rust editions

## Usage
Add `libxdp-sys` to your `Cargo.toml`:

```toml
[dependencies]
libxdp-sys = "0.2"
```

Enable optional features as needed:
```toml
[features]
vendored = ["libbpf-sys/vendored"]
vendored-libelf = ["libbpf-sys/vendored-libelf"]
```

Example usage:
```rust
use libxdp_sys::*;

// Access a constant
let headroom = XDP_PACKET_HEADROOM;

// Use a struct and call a method
let insn = bpf_insn {
	code: BPF_LD as u8,
	_bitfield_align_1: [],
	_bitfield_1: bpf_insn::new_bitfield_1(1, 2),
	off: 0,
	imm: 0,
};
let dst_reg = insn.dst_reg();
```

## Building
This crate uses a `build.rs` script to generate bindings at build time. For most users, enabling the `vendored` feature will build libbpf from source automatically.

## Testing
Run integration tests with:
```sh
cargo test
```

## License
`libxdp-sys` is dual-licensed under LGPL-2.1 or BSD-2-Clause, matching the upstream libxdp library.

## Links
- [libxdp upstream](https://github.com/xdp-project/xdp-tools/tree/main/lib/libxdp)
- [libbpf-sys crate](https://crates.io/crates/libbpf-sys)

## Authors
- Hengqi Chen <hengqi.chen@gmail.com>
- Nathanial Lattimer <d0nut@resync.gg>
- Karsten Becker <skipper.pasty.0a@icloud.com>

