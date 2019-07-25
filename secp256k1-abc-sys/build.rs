use std::process::Command;
use std::path::PathBuf;
use std::env;
use std::fs;
use cmake;
use bindgen;

fn download_deps(out_path: &PathBuf, base_url: &str) {
    Command::new("svn")
        .arg("export")
        .arg(format!("{}src/secp256k1", base_url))
        .arg(out_path.join("cmake/secp256k1"))
        .arg("--force")
        .output()
        .unwrap();

    Command::new("svn")
        .arg("export")
        .arg(format!("{}cmake/modules", base_url))
        .arg(out_path.join("cmake/modules"))
        .arg("--force")
        .output()
        .unwrap();
}

fn compile_lib(out_path: &PathBuf) {
    let dst = cmake::Config::new(out_path.join("cmake"))
        .build_target("")
        .define("SECP256K1_BUILD_TEST", "OFF")
        .define("SECP256K1_ENABLE_MODULE_ECDH", "ON")
        .build();

    println!("cargo:rustc-link-search=native={}", dst.join("build/secp256k1/").display());
    println!("cargo:rustc-link-lib=static=secp256k1");
}

fn generate_bindings(out_path: &PathBuf) {
    let headers = [
        "cmake/secp256k1/include/secp256k1_ecdh.h",
        "cmake/secp256k1/include/secp256k1_multiset.h",
        "cmake/secp256k1/include/secp256k1_recovery.h",
        "cmake/secp256k1/include/secp256k1_schnorr.h",
        "cmake/secp256k1/include/secp256k1.h",
    ];

    let bindings = headers.iter()
        .map(|h| {
            out_path.join(h).into_os_string().into_string().unwrap()
        })
        .fold(bindgen::Builder::default(), |b, h| {
            b.header(h)
        })
        .opaque_type("secp256k1_context_struct")
        .opaque_type("secp256k1_pubkey")
        .opaque_type("secp256k1_ecdsa_signature")
        .opaque_type("secp256k1_multiset")
        .opaque_type("secp256k1_ecdsa_recoverable_signature")
        .generate()
        .unwrap();

    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();
}

fn main() {
    const DEFAULT_URL: &'static str = "https://github.com/Bitcoin-ABC/bitcoin-abc/tags/v0.19.6/";
    let base_url = match env::var("BITCOIN_ABC_REPO_URL") {
        Ok(ref s) if !s.is_empty() => s.to_string(),
        _ => DEFAULT_URL.to_string(),
    };

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    if !out_path.join("cmake/secp256k1").exists() || !out_path.join("cmake/modules").exists() {
        println!("download deps from {} ...", base_url);
        download_deps(&out_path, &base_url);

        fs::copy("cmake/CMakeLists.txt", out_path.join("cmake/CMakeLists.txt")).unwrap();
    }

    compile_lib(&out_path);

    generate_bindings(&out_path);
}
