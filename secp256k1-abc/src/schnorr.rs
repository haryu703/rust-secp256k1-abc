use std::ptr;
use std::os::raw::c_void;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, nonce_function};
use super::utils::convert_return;

pub fn verify(ctx: &Context, sig: &[u8; 64], msg: &[u8; 32], pubkey: &PublicKey) -> Result<()> {
    let ret = unsafe {
        secp256k1_schnorr_verify(ctx.ctx, sig.as_ptr(), msg.as_ptr(), &pubkey.raw)
    };
    convert_return(ret, ())
}

pub fn sign<F>(ctx: &Context, msg: &[u8; 32], seckey: &PrivateKey, nonce_closure: Option<F>) -> Result<[u8; 64]>
    where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
    let mut sig = [0; 64];
    let ret = match nonce_closure {
        Some(mut f) => {
            let mut cb = &mut f;
            let cb = &mut cb;
            unsafe { secp256k1_schnorr_sign(ctx.ctx, sig.as_mut_ptr(), msg.as_ptr(), seckey.raw.as_ptr(), Some(nonce_function), cb as *const _ as *const c_void) }
        },
        None => unsafe { secp256k1_schnorr_sign(ctx.ctx, sig.as_mut_ptr(), msg.as_ptr(), seckey.raw.as_ptr(), None, ptr::null()) }
    };
    convert_return(ret, sig)
}
