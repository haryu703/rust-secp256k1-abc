use secp256k1_abc_sys::*;
use super::context::Context;
use super::{Result, Error};

#[derive(Clone)]
pub struct PrivateKey<'a> {
    pub(crate) raw: [u8; 32],
    pub(crate) ctx: &'a Context,
}

impl<'a> PrivateKey<'a> {
    pub fn from_array(ctx: &'a Context, raw: [u8; 32]) -> Self {
        PrivateKey {
            raw,
            ctx,
        }
    }

    pub fn serialize(&self) -> &[u8; 32] {
        &self.raw
    }

    pub fn verify(&self) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_seckey_verify(self.ctx.ctx, self.raw.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn negate(&mut self) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_privkey_negate(self.ctx.ctx, self.raw.as_mut_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn tweak_add(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_privkey_tweak_add(self.ctx.ctx, self.raw.as_mut_ptr(), tweak.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn tweak_mul(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_privkey_tweak_mul(self.ctx.ctx, self.raw.as_mut_ptr(), tweak.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

}
