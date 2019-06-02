mod context;
mod public_key;
mod ecdsa_signature;
mod utils;
mod private_key;
pub mod ecdh;
mod multiset;
mod ecdsa_recoverable_signature;
pub mod schnorr;

#[macro_use] extern crate bitflags;
use std::mem;
use std::convert::TryInto;
use secp256k1_abc_sys::*;

pub use context::{Context, ContextFlag};
pub use public_key::PublicKey;
pub use ecdsa_signature::ECDSASignature;
pub use private_key::PrivateKey;
pub use multiset::MultiSet;
pub use ecdsa_recoverable_signature::ECDSARecoverableSignature;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;


bitflags! {
    pub struct ECFlag: u32 {
        const COMPRESSED = SECP256K1_EC_COMPRESSED;
        const UNCOMPRESSED = SECP256K1_EC_UNCOMPRESSED;
    }
}
pub mod nonce_function {
    pub use secp256k1_abc_sys::secp256k1_nonce_function_rfc6979 as rfc6979;
    pub use secp256k1_abc_sys::secp256k1_nonce_function_default as default;
}
pub mod tag_pub_key {
    use secp256k1_abc_sys::*;
    pub const EVEN: u32 = SECP256K1_TAG_PUBKEY_EVEN;
    pub const ODD: u32 = SECP256K1_TAG_PUBKEY_ODD;
    pub const UNCOMPRESSED: u32 = SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
    pub const HYBRID_EVEN: u32 = SECP256K1_TAG_PUBKEY_HYBRID_EVEN;
    pub const HYBRID_ODD: u32 = SECP256K1_TAG_PUBKEY_HYBRID_ODD;
}

pub type Result<T> = std::result::Result<T, ::std::os::raw::c_int>;

macro_rules! ptr_to_mut_slice {
    ($p:expr, $len:expr) => {
        if $p.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts_mut($p, $len) }.try_into().unwrap())
        }
    };
}

macro_rules! ptr_to_slice {
    ($p:expr, $len:expr) => {
        if $p.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts($p, $len) }.try_into().unwrap())
        }
    };
}

type NonceClosure = FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32;

extern "C" fn nonce_function(
    nonce32: *mut ::std::os::raw::c_uchar,
    msg32: *const ::std::os::raw::c_uchar,
    key32: *const ::std::os::raw::c_uchar,
    algo16: *const ::std::os::raw::c_uchar,
    data: *mut ::std::os::raw::c_void,
    attempt: ::std::os::raw::c_uint,
) -> ::std::os::raw::c_int {
    let closure: &mut &mut NonceClosure = unsafe { mem::transmute(data) };
    let nonce = ptr_to_mut_slice!(nonce32, 32);
    let msg = ptr_to_slice!(msg32, 32);
    let key = ptr_to_slice!(key32, 32);
    let algo = ptr_to_slice!(algo16, 16);
    closure(nonce, msg, key, algo, attempt)
}
