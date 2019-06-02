use std::ptr;
use std::os::raw::c_void;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, nonce_function};
use super::utils::convert_return;

pub struct ECDSASignature<'a> {
    pub(crate) raw: secp256k1_ecdsa_signature,
    ctx: &'a Context,
}

impl<'a> ECDSASignature<'a> {
    pub(crate) fn new(ctx: &'a Context) -> Self {
        ECDSASignature {
            raw: secp256k1_ecdsa_signature {
                _bindgen_opaque_blob: [0; 64],
            },
            ctx,
        }
    }

    pub fn parse_compact(ctx: &'a Context, input: &[u8; 64]) -> Result<Self> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_signature_parse_compact(ctx.ctx, &mut sig.raw, input.as_ptr())
        };
        convert_return(ret, sig)
    }

    pub fn parse_der(ctx: &'a Context, input: &[u8]) -> Result<(Self)> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_signature_parse_der(ctx.ctx, &mut sig.raw, input.as_ptr(), input.len())
        };
        convert_return(ret, sig)
    }

    pub fn serialize_der<'b>(&self, output: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut outputlen = output.len();
        let ret = unsafe {
            secp256k1_ecdsa_signature_serialize_der(self.ctx.ctx, output.as_mut_ptr(), &mut outputlen, &self.raw)
        };
        convert_return(ret, &output[..outputlen])
    }

    pub fn serialize_compact(&self, output: &mut [u8; 64]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ecdsa_signature_serialize_compact(self.ctx.ctx, output.as_mut_ptr(), &self.raw)
        };
        convert_return(ret, ())
    }

    pub fn normalize(&self, only_check: bool) -> Result<Option<Self>> {
        if only_check {
            let ret = unsafe {
                secp256k1_ecdsa_signature_normalize(self.ctx.ctx, ptr::null_mut(), &self.raw)
            };
            convert_return(ret, None)
        } else {
            let mut sig = Self::new(self.ctx);
            let ret = unsafe {
                secp256k1_ecdsa_signature_normalize(self.ctx.ctx, &mut sig.raw, &self.raw)
            };
            convert_return(ret, Some(sig))
        }
    }

    pub fn verify(&self, msg: &[u8; 32], pubkey: &PublicKey) -> Result<()> {
        let ret = unsafe {
            secp256k1_ecdsa_verify(self.ctx.ctx, &self.raw, msg.as_ptr(), &pubkey.raw)
        };
        convert_return(ret, ())
    }

    pub fn sign_with_nonce_closure<F>(ctx: &'a Context, msg: &[u8; 32], seckey: &PrivateKey, mut nonce_closure: F) -> Result<Self>
        where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
        let mut sig = Self::new(ctx);
        let mut cb = &mut nonce_closure;
        let cb = &mut cb;
        let ret = unsafe {
            secp256k1_ecdsa_sign(ctx.ctx, &mut sig.raw, msg.as_ptr(), seckey.raw.as_ptr(), Some(nonce_function), cb as *const _ as *const c_void)
        };
        convert_return(ret, sig)
    }

    pub fn sign(ctx: &'a Context, msg: &[u8; 32], seckey: &PrivateKey) -> Result<Self> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_sign(ctx.ctx, &mut sig.raw, msg.as_ptr(), seckey.raw.as_ptr(), None, ptr::null())
        };
        convert_return(ret, sig)
    }
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

        let sig = ECDSASignature::sign(&ctx, &msg, &privkey).unwrap();
        assert!(sig.verify(&msg, &pubkey).is_ok());
    }
}
