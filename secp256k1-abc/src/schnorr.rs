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

pub fn sign_with_nonce_closure<F>(ctx: &Context, msg: &[u8; 32], seckey: &PrivateKey, mut nonce_closure: F) -> Result<[u8; 64]>
    where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
    let mut sig = [0; 64];
    let mut cb = &mut nonce_closure;
    let cb = &mut cb;
    let ret = unsafe {
        secp256k1_schnorr_sign(ctx.ctx, sig.as_mut_ptr(), msg.as_ptr(), seckey.raw.as_ptr(), Some(nonce_function), cb as *const _ as *const c_void)
    };
    convert_return(ret, sig)
}

pub fn sign(ctx: &Context, msg: &[u8; 32], seckey: &PrivateKey) -> Result<[u8; 64]> {
    let mut sig = [0; 64];
    let ret = unsafe {
        secp256k1_schnorr_sign(ctx.ctx, sig.as_mut_ptr(), msg.as_ptr(), seckey.raw.as_ptr(), None, ptr::null())
    };
    convert_return(ret, sig)
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::ContextFlag;

    #[test]
    fn sign_verify() {
        let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);
        let msg = hex!("4f1379111cc4350a52280fca4f21673ec8db83edaa9be0731fd9fe6aa4d63c5e");

        let privkey = PrivateKey::from_array(&ctx, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::create(&ctx, &privkey).unwrap();

        let sig = sign(&ctx, &msg, &privkey).unwrap();
        assert!(verify(&ctx, &sig, &msg, &pubkey).is_ok());
    }
}
