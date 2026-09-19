fn main() {
    println!("cargo:rerun-if-changed=VERSION");
    let release_version = std::fs::read_to_string("VERSION")
        .expect("read VERSION")
        .trim()
        .to_owned();
    println!("cargo:rustc-env=BAZALT_RELEASE_VERSION={release_version}");

    if std::env::var_os("CARGO_FEATURE_AFXDP").is_some() {
        println!("cargo:rerun-if-changed=native/afxdp.c");
        println!("cargo:rerun-if-changed=native/throttle.c");
        println!("cargo:rerun-if-changed=native/throttle.bpf.c");

        let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        let throttle_object = out_dir.join("bazalt-throttle.bpf.o");
        let clang = std::env::var_os("CLANG").unwrap_or_else(|| "clang".into());
        let output = std::process::Command::new(clang)
            .args(["-target", "bpf", "-O2", "-g", "-c"])
            .arg("native/throttle.bpf.c")
            .arg("-o")
            .arg(&throttle_object)
            .output()
            .expect("run clang for throttle BPF program");
        if !output.status.success() {
            panic!(
                "cannot compile native/throttle.bpf.c: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        println!(
            "cargo:rustc-env=BAZALT_THROTTLE_BPF_OBJECT={}",
            throttle_object.display()
        );

        cc::Build::new()
            .files(["native/afxdp.c", "native/throttle.c"])
            .flag_if_supported("-O3")
            .compile("bazalt_native");
        println!("cargo:rustc-link-lib=xdp");
        println!("cargo:rustc-link-lib=bpf");
        println!("cargo:rustc-link-lib=elf");
        println!("cargo:rustc-link-lib=z");
    }
}
