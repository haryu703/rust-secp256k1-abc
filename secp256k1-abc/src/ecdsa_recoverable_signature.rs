use std::ptr;
use std::convert::TryFrom;
use std::os::raw::c_void;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, Error};
use super::ecdsa_signature::ECDSASignature;
use super::nonce_function::{nonce_function, NonceClosure};

pub struct ECDSARecoverableSignature<'a, 'b> {
    raw: secp256k1_ecdsa_recoverable_signature,
    ctx: &'a Context<'b>,
}

impl<'a, 'b> TryFrom<ECDSARecoverableSignature<'a, 'b>> for ECDSASignature<'a, 'b> {
    type Error = Error;

    fn try_from(rec: ECDSARecoverableSignature<'a, 'b>) -> Result<ECDSASignature<'a, 'b>> {
        let mut sig = ECDSASignature::new(rec.ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_convert(rec.ctx.ctx, &mut sig.raw, &rec.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }
}

impl<'a, 'b> ECDSARecoverableSignature<'a, 'b> {
    fn new(ctx: &'a Context<'b>) -> Self {
        ECDSARecoverableSignature {
            raw: secp256k1_ecdsa_recoverable_signature {
                _bindgen_opaque_blob: [0; 65]
            },
            ctx
        }
    }

    pub fn parse_compact(ctx: &'a Context<'b>, input: &[u8; 64], recid: i32) -> Result<Self> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.ctx, &mut sig.raw, input.as_ptr(), recid)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn convert<'c: 'b>(&'c self) -> Result<ECDSASignature> {
        let mut sig = ECDSASignature::new(self.ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_convert(self.ctx.ctx, &mut sig.raw, &self.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn serialize_compact(&self) -> Result<([u8; 64], i32)> {
        let mut output = [0; 64];
        let mut recid = 0;
        let ret = unsafe {
            secp256k1_ecdsa_recoverable_signature_serialize_compact(self.ctx.ctx, output.as_mut_ptr(), &mut recid, &self.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok((output, recid))
        }
    }

    pub fn sign_with_nonce_closure<F>(ctx: &'a Context<'b>, msg: &[u8; 32], seckey: &PrivateKey, mut nonce_closure: F) -> Result<Self>
        where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
        let mut sig = Self::new(ctx);
        let mut obj: NonceClosure = &mut nonce_closure;
        let data = &mut obj as *const _ as *const c_void;
        let ret = unsafe {
            secp256k1_ecdsa_sign_recoverable(
                ctx.ctx,
                &mut sig.raw,
                msg.as_ptr(),
                seckey.raw.as_ptr(),
                Some(nonce_function),
                data
            )
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn sign(ctx: &'a Context<'b>, msg: &[u8; 32], seckey: &PrivateKey) -> Result<Self> {
        let mut sig = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ecdsa_sign_recoverable(ctx.ctx, &mut sig.raw, msg.as_ptr(), seckey.raw.as_ptr(), None, ptr::null())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(sig)
        }
    }

    pub fn recover<'c: 'b>(&'c self, msg: &[u8; 32]) -> Result<PublicKey> {
        let mut key = PublicKey::new(self.ctx);
        let ret = unsafe {
            secp256k1_ecdsa_recover(self.ctx.ctx, &mut key.raw, &self.raw, msg.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(key)
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;
    use std::convert::TryInto;
    use super::*;
    use super::super::ContextFlag;

    #[test]
    fn sign_verify() {
        let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);
        let msg = hex!("4f1379111cc4350a52280fca4f21673ec8db83edaa9be0731fd9fe6aa4d63c5e");

        let privkey = PrivateKey::from_array(&ctx, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::try_from(&privkey).unwrap();

        let rec_sig = ECDSARecoverableSignature::sign(&ctx, &msg, &privkey).unwrap();

        let sig: ECDSASignature = rec_sig.try_into().unwrap();
        assert!(sig.verify(&msg, &pubkey).is_ok());
    }
}
