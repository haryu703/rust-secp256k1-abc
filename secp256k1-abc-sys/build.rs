use std::process::Command;
use std::path::PathBuf;
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use cmake;
use bindgen;

fn setup_cmake(out_path: &PathBuf) -> std::io::Result<()> {
    Command::new("./init.sh").output()?;

    let cmake_path = out_path.join("cmake");

    if !cmake_path.exists() {
        fs::create_dir(&cmake_path)?;
    }
    if cmake_path.join("secp256k1").read_link().is_err() {
        symlink(fs::canonicalize("./bitcoin-abc/src/secp256k1/")?, cmake_path.join("secp256k1"))?;
    }
    if cmake_path.join("modules").read_link().is_err() {
        symlink(fs::canonicalize("./bitcoin-abc/cmake/modules/")?, cmake_path.join("modules"))?;
    }
    fs::copy("cmake/CMakeLists.txt", cmake_path.join("CMakeLists.txt"))?;

    Ok(())
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
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    setup_cmake(&out_path).unwrap();
    compile_lib(&out_path);

    generate_bindings(&out_path);
}
