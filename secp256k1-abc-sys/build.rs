use std::path::PathBuf;
use std::env;
use cmake;
use bindgen;

fn compile_lib() {
    let dst = cmake::Config::new("cmake")
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
        .fold(bindgen::Builder::default(), |b, h| {
            b.header(h.to_string())
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
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    compile_lib();

    generate_bindings(&out_path);
}
