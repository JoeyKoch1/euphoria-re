use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    for path in [
        "src/abi.rs",
        "cbindgen.toml",
        "../CMakeLists.txt",
        "../core",
        "../db",
        "../simd",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    generate_header();
    build_native();
    link_cpp_runtime();
}

fn generate_header() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config = cbindgen::Config::from_file("cbindgen.toml").unwrap();
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("failed to generate euphoria.h")
        .write_to_file("euphoria.h");
}

fn build_native() {
    let out = cmake::Config::new("..").generator("Ninja").build();
    println!("cargo:rustc-link-search=native={}/lib", out.display());
    for lib in ["eu_core", "eu_db", "eu_simd"] {
        println!("cargo:rustc-link-lib=static={lib}");
    }
}

fn link_cpp_runtime() {
    let target = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    if target == "msvc" {
        return;
    }
    let output = Command::new("g++")
        .arg("-print-file-name=libstdc++.a")
        .output()
        .expect("g++ not found");
    let path = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
    println!(
        "cargo:rustc-link-search=native={}",
        path.parent().unwrap().display()
    );
    println!("cargo:rustc-link-lib=static:-bundle=stdc++");
}
