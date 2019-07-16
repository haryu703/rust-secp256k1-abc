use std::ptr;
use std::os::raw::c_void;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, Error};
use super::nonce_function::{nonce_function, NonceClosure};

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
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn parse_der(ctx: &'a Context, input: &[u8]) -> Result<(Self)> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_signature_parse_der(ctx.ctx, &mut sig.raw, input.as_ptr(), input.len())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn serialize_der<'b>(&self, output: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut outputlen = output.len();
        let ret = unsafe {
            secp256k1_ecdsa_signature_serialize_der(self.ctx.ctx, output.as_mut_ptr(), &mut outputlen, &self.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(&output[..outputlen])
        }
    }

    pub fn serialize_compact(&self, output: &mut [u8; 64]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ecdsa_signature_serialize_compact(self.ctx.ctx, output.as_mut_ptr(), &self.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn normalize(&self, only_check: bool) -> Result<Option<Self>> {
        let (ret, sig) = if only_check {
            let ret = unsafe {
                secp256k1_ecdsa_signature_normalize(self.ctx.ctx, ptr::null_mut(), &self.raw)
            };
            (ret, None)
        } else {
            let mut sig = Self::new(self.ctx);
            let ret = unsafe {
                secp256k1_ecdsa_signature_normalize(self.ctx.ctx, &mut sig.raw, &self.raw)
            };
            (ret, Some(sig))
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn verify(&self, msg: &[u8; 32], pubkey: &PublicKey) -> Result<()> {
        let ret = unsafe {
            secp256k1_ecdsa_verify(self.ctx.ctx, &self.raw, msg.as_ptr(), &pubkey.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn sign_with_nonce_closure<F>(ctx: &'a Context, msg: &[u8; 32], seckey: &PrivateKey, mut nonce_closure: F) -> Result<Self>
        where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
        let mut sig = Self::new(ctx);
        let mut obj: NonceClosure = &mut nonce_closure;
        let data = &mut obj as *const _ as *const c_void;
        let ret = unsafe {
            secp256k1_ecdsa_sign(
                ctx.ctx,
                &mut sig.raw,
                msg.as_ptr(),
                seckey.raw.as_ptr(),
                Some(nonce_function),
                data,
            )
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn sign(ctx: &'a Context, msg: &[u8; 32], seckey: &PrivateKey) -> Result<Self> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_sign(ctx.ctx, &mut sig.raw, msg.as_ptr(), seckey.raw.as_ptr(), None, ptr::null())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;
    use super::*;
    use super::super::ContextFlag;

    #[test]
    fn sign_verify() {
        let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);
        let msg = hex!("4f1379111cc4350a52280fca4f21673ec8db83edaa9be0731fd9fe6aa4d63c5e");

        let privkey = PrivateKey::from_array(&ctx, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::try_from(&privkey).unwrap();

        let sig = ECDSASignature::sign(&ctx, &msg, &privkey).unwrap();
        assert!(sig.verify(&msg, &pubkey).is_ok());
    }

    #[test]
    fn with_custom_nonce() {
        let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);
        let msg = hex!("4f1379111cc4350a52280fca4f21673ec8db83edaa9be0731fd9fe6aa4d63c5e");

        let privkey = PrivateKey::from_array(&ctx, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::try_from(&privkey).unwrap();

        let sig = ECDSASignature::sign_with_nonce_closure(
            &ctx,
            &msg,
            &privkey,
            |nonce, msg, key, algo, attempt| {
                assert!(nonce.is_some());
                assert!(msg.is_some());
                assert!(key.is_some());
                assert!(algo.is_some());
                assert!(attempt == 0);

                if let Some(n) = nonce {
                    n[0] = 0xff;
                }

                1
            },
        ).unwrap();
        assert!(sig.verify(&msg, &pubkey).is_ok());
    }
}
