fn main() {
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
