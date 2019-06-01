use std::process::Command;
use std::path::{Path, PathBuf};
use std::env;
use cmake;
use bindgen;

fn download_deps(base_url: &str) {
    Command::new("svn")
        .arg("export")
        .arg(format!("{}src/secp256k1", base_url))
        .arg("cmake/secp256k1")
        .arg("--force")
        .output()
        .unwrap();

    Command::new("svn")
        .arg("export")
        .arg(format!("{}cmake/modules", base_url))
        .arg("cmake/modules")
        .arg("--force")
        .output()
        .unwrap();
}

fn compile_lib() {
    let dst = cmake::Config::new("cmake")
        .build_target("")
        .define("SECP256K1_BUILD_TEST", "OFF")
        .define("SECP256K1_ENABLE_MODULE_ECDH", "ON")
        .build();

    println!("cargo:rustc-link-search=native={}", dst.join("build/secp256k1/").display());
    println!("cargo:rustc-link-lib=static=secp256k1");
}

fn generate_bindings() {
    let bindings = bindgen::Builder::default()
        .header("cmake/secp256k1/include/secp256k1_ecdh.h")
        .header("cmake/secp256k1/include/secp256k1_multiset.h")
        .header("cmake/secp256k1/include/secp256k1_recovery.h")
        .header("cmake/secp256k1/include/secp256k1_schnorr.h")
        .header("cmake/secp256k1/include/secp256k1.h")
        .opaque_type("secp256k1_context_struct")
        .opaque_type("secp256k1_pubkey")
        .opaque_type("secp256k1_ecdsa_signature")
        .opaque_type("secp256k1_multiset")
        .opaque_type("secp256k1_ecdsa_recoverable_signature")
        .generate()
        .unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();
}

fn main() {
    const DEFAULT_URL: &'static str = "https://github.com/Bitcoin-ABC/bitcoin-abc/tags/v0.19.6/";
    let base_url = match env::var("BITCOIN_ABC_REPO_URL") {
        Ok(ref s) if !s.is_empty() => s.to_string(),
        _ => DEFAULT_URL.to_string(),
    };

    if !Path::new("cmake/secp256k1").exists() || !Path::new("cmake/modules").exists() {
        println!("download deps from {} ...", base_url);
        download_deps(&base_url);
    }

    compile_lib();

    generate_bindings();
}
