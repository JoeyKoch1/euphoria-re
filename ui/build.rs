use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/euphoria.rc");
    println!("cargo:rerun-if-changed=assets/favicon.ico");
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
        return;
    }

    let msvc = env::var("CARGO_CFG_TARGET_ENV").unwrap() == "msvc";
    let resource = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(if msvc {
        "euphoria.res"
    } else {
        "euphoria.o"
    });
    let mut command = if msvc {
        let mut command = Command::new("rc");
        command.args(["/nologo", "/fo"]).arg(&resource);
        command.arg("euphoria.rc");
        command
    } else {
        let mut command = Command::new("windres");
        command.args(["-i", "euphoria.rc", "-O", "coff", "-o"]);
        command.arg(&resource);
        command
    };
    let status = command
        .current_dir("assets")
        .status()
        .expect("Windows resource compiler not found");
    assert!(status.success(), "failed to compile Euphoria's icon");
    println!("cargo:rustc-link-arg-bin=euphoria={}", resource.display());
}
