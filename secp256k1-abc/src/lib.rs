mod context;
mod public_key;
mod ecdsa_signature;
mod private_key;
pub mod ecdh;
mod multiset;
mod ecdsa_recoverable_signature;
pub mod schnorr;
mod error;
mod nonce_function;

#[macro_use] extern crate bitflags;
use secp256k1_abc_sys::*;

pub use context::{Context, ContextFlag, IllegalClosure, ErrorClosure};
pub use public_key::PublicKey;
pub use ecdsa_signature::ECDSASignature;
pub use private_key::PrivateKey;
pub use multiset::MultiSet;
pub use ecdsa_recoverable_signature::ECDSARecoverableSignature;
pub use error::*;
pub use nonce_function::NonceClosure;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;


bitflags! {
    pub struct ECFlag: u32 {
        const COMPRESSED = SECP256K1_EC_COMPRESSED;
        const UNCOMPRESSED = SECP256K1_EC_UNCOMPRESSED;
    }
}
pub mod tag_pub_key {
    use secp256k1_abc_sys::*;
    pub const EVEN: u32 = SECP256K1_TAG_PUBKEY_EVEN;
    pub const ODD: u32 = SECP256K1_TAG_PUBKEY_ODD;
    pub const UNCOMPRESSED: u32 = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
    pub const HYBRID_EVEN: u32 = SECP256K1_TAG_PUBKEY_HYBRID_EVEN;
    pub const HYBRID_ODD: u32 = SECP256K1_TAG_PUBKEY_HYBRID_ODD;
}
