use std::ptr;
use std::os::raw::c_void;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, nonce_function};
use super::utils::convert_return;
use super::ecdsa_signature::ECDSASignature;

pub struct ECDSARecoverableSignature<'a> {
    raw: secp256k1_ecdsa_recoverable_signature,
    ctx: &'a Context,
}

impl<'a> ECDSARecoverableSignature<'a> {
    fn new(ctx: &'a Context) -> Self {
        ECDSARecoverableSignature {
            raw: secp256k1_ecdsa_recoverable_signature {
                _bindgen_opaque_blob: [0; 65]
            },
            ctx
        }
    }

    pub fn parse_compact(ctx: &'a Context, input: &[u8; 64], recid: i32) -> Result<Self> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.ctx, &mut sig.raw, input.as_ptr(), recid)
        };
        convert_return(ret, sig)
    }

    pub fn convert(&self) -> Result<ECDSASignature> {
        let mut sig = ECDSASignature::new(self.ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_convert(self.ctx.ctx, &mut sig.raw, &self.raw)
        };
        convert_return(ret, sig)
    }

    pub fn serialize_compact(&self) -> Result<([u8; 64], i32)> {
        let mut output = [0; 64];
        let mut recid = 0;
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_serialize_compact(self.ctx.ctx, output.as_mut_ptr(), &mut recid, &self.raw)
        };
        convert_return(ret, (output, recid))
    }

    pub fn sign<F>(ctx: &'a Context, msg: &[u8; 32], seckey: &PrivateKey, nonce_closure: Option<F>) -> Result<Self>
        where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
        let mut sig = Self::new(ctx);
        let ret = match nonce_closure {
            Some(mut f) => {
                let mut cb = &mut f;
                let cb = &mut cb;
                unsafe { secp256k1_ecdsa_sign_recoverable(ctx.ctx, &mut sig.raw, msg.as_ptr(), seckey.raw.as_ptr(), Some(nonce_function), cb as *const _ as *const c_void) }
            },
            None => unsafe { secp256k1_ecdsa_sign_recoverable(ctx.ctx, &mut sig.raw, msg.as_ptr(), seckey.raw.as_ptr(), None, ptr::null()) }
        };
        convert_return(ret, sig)
    }

    pub fn recover(&self, msg: &[u8; 32]) -> Result<PublicKey> {
        let mut key = PublicKey::new(self.ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recover(self.ctx.ctx, &mut key.raw, &self.raw, msg.as_ptr())
        };
        convert_return(ret, key)
    }
}
