fn main() {
    println!("cargo:rerun-if-changed=VERSION");
    let release_version = std::fs::read_to_string("VERSION")
        .expect("read VERSION")
        .trim()
        .to_owned();
    println!("cargo:rustc-env=BAZALT_RELEASE_VERSION={release_version}");

    if std::env::var_os("CARGO_FEATURE_AFXDP").is_some() {
        println!("cargo:rerun-if-changed=native/afxdp.c");
        cc::Build::new()
            .file("native/afxdp.c")
            .flag_if_supported("-O3")
            .compile("bazalt_afxdp");
        println!("cargo:rustc-link-lib=xdp");
        println!("cargo:rustc-link-lib=bpf");
        println!("cargo:rustc-link-lib=elf");
        println!("cargo:rustc-link-lib=z");
    }
}
