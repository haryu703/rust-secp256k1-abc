use secp256k1_abc_sys::*;
use super::context::Context;
use super::Result;
use super::utils::convert_return;

pub struct PrivateKey<'a> {
    pub(crate) raw: [u8; 32],
    ctx: &'a Context,
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
        convert_return(ret, ())
    }

    pub fn negate(&mut self) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_privkey_negate(self.ctx.ctx, self.raw.as_mut_ptr())
        };
        convert_return(ret, ())
    }

    pub fn tweak_add(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_privkey_tweak_add(self.ctx.ctx, self.raw.as_mut_ptr(), tweak.as_ptr())
        };
        convert_return(ret, ())
    }

    pub fn tweak_mul(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_privkey_tweak_mul(self.ctx.ctx, self.raw.as_mut_ptr(), tweak.as_ptr())
        };
        convert_return(ret, ())
    }

}
