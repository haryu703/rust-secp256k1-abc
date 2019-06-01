use secp256k1_abc_sys::*;
use super::context::Context;
use super::private_key::PrivateKey;
use super::{Result, ECFlag};
use super::utils::convert_return;

pub struct PublicKey<'a> {
    pub(crate) raw: secp256k1_pubkey,
    ctx: &'a Context,
}

impl<'a> PublicKey<'a> {
    pub(crate) fn new(ctx: &'a Context) -> Self {
        PublicKey {
            raw: secp256k1_pubkey {
                _bindgen_opaque_blob: [0; 64],
            },
            ctx,
        }
    }

    pub fn parse(ctx: &'a Context, input: &[u8]) -> Result<Self> {
        let mut key = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ec_pubkey_parse(ctx.ctx, &mut key.raw, input.as_ptr(), input.len())
        };
        convert_return(ret, key)
    }

    pub fn serialize<'b>(&self, output: &'b mut [u8], flags: ECFlag) -> Result<&'b [u8]> {
        let mut outputlen = output.len();
        let ret = unsafe {
            secp256k1_ec_pubkey_serialize(self.ctx.ctx, output.as_mut_ptr(), &mut outputlen, &self.raw, flags.bits)
        };
        convert_return(ret, &output[..outputlen])
    }

    pub fn create(ctx: &'a Context, seckey: &PrivateKey) -> Result<Self> {
        let mut key = Self::new(ctx);
        let ret = unsafe {
            secp256k1_ec_pubkey_create(ctx.ctx, &mut key.raw, seckey.raw.as_ptr())
        };
        convert_return(ret, key)
    }

    pub fn negate(&mut self) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_pubkey_negate(self.ctx.ctx, &mut self.raw)
        };
        convert_return(ret, ())
    }

    pub fn tweak_add(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_pubkey_tweak_add(self.ctx.ctx, &mut self.raw, tweak.as_ptr())
        };
        convert_return(ret, ())
    }

    pub fn tweak_mul(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_pubkey_tweak_mul(self.ctx.ctx, &mut self.raw, tweak.as_ptr())
        };
        convert_return(ret, ())
    }

    pub fn combine(ctx: &'a Context, ins: &[PublicKey]) -> Result<Self> {
        let mut key = Self::new(ctx);
        let keys = ins.iter().map(|v| &v.raw as *const _).collect::<Vec<_>>().as_ptr();
        let ret = unsafe {
            secp256k1_ec_pubkey_combine(ctx.ctx, &mut key.raw, keys, ins.len())
        };
        convert_return(ret, key)
    }
}
