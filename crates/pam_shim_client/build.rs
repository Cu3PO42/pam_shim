fn main() {
    let current_dir = std::env::current_dir().unwrap();
    let version_script = current_dir.join("pam_shim.map");

    println!("cargo::rustc-link-arg-cdylib=-fuse-ld=lld");
    println!("cargo::rustc-link-arg-cdylib=-Wl,-soname,libpam");
    println!("cargo::rustc-link-arg-cdylib=-Wl,--version-script={}", version_script.display());
    for fun in &[
        "pam_start",
        "pam_start_confdir",
        "pam_end",
        "pam_setcred",
        "pam_authenticate",
        "pam_acct_mgmt",
        "pam_open_session",
        "pam_close_session",
        "pam_chauthtok",
    ] {
        println!("cargo::rustc-link-arg-cdylib=-Wl,--defsym={}={}_impl", fun, fun);
    }
}