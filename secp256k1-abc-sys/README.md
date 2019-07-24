# Binding of libsecp256k1 of Bitcoin ABC implementation
## Prerequirement
- CMake v3.5~  
    Used for compiling libsecp256k1.
- clang v3.7~
    Used for generating bindings.  
    More info: https://github.com/rust-lang/rust-bindgen/blob/master/book/src/requirements.md  
- svn  
    Used for downloading sources of libsecp256k1 from github.

## Environment variable
You can customize build step using following environment variables.
- BITCOIN_ABC_REPO_URL  
    default: https://github.com/Bitcoin-ABC/bitcoin-abc/tags/v0.19.6/  
    Repository of Bitcoin ABC.  
    libsecp256k1 sources are downloaded from ${BITCOIN_ABC_REPO_URL}src/secp256k1 .
