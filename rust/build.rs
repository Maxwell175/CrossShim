//! Build script for libafl_qemu_bridge
//!
//! Generates C header file using cbindgen

use std::env;
use std::path::PathBuf;

fn main() {
    // Generate C header using cbindgen
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let output_dir = PathBuf::from(&crate_dir).join("..").join("include").join("qemu");

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&output_dir).ok();

    let config = cbindgen::Config::from_file("cbindgen.toml")
        .unwrap_or_default();

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(output_dir.join("qemu_bridge_generated.h"));

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
