use std::convert::TryFrom;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::private_key::PrivateKey;
use super::{Result, Error, ECFlag};

pub struct PublicKey<'a> {
    pub(crate) raw: secp256k1_pubkey,
    ctx: &'a Context,
}

impl<'a> TryFrom<&PrivateKey<'a>> for PublicKey<'a> {
    type Error = Error;
    fn try_from(seckey: &PrivateKey<'a>) -> Result<Self> {
        let mut key = Self::new(seckey.ctx);
        let ret = unsafe {
            secp256k1_ec_pubkey_create(seckey.ctx.ctx, &mut key.raw, seckey.raw.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(key)
        }
    }
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
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(key)
        }
    }

    pub fn serialize<'b>(&self, output: &'b mut [u8], flags: ECFlag) -> Result<&'b [u8]> {
        let mut outputlen = output.len();
        let ret = unsafe {
            secp256k1_ec_pubkey_serialize(self.ctx.ctx, output.as_mut_ptr(), &mut outputlen, &self.raw, flags.bits)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(&output[..outputlen])
        }
    }

    pub fn serialize_compressed(&self) -> Result<[u8;33]> {
        let mut output = [0;33];
        self.serialize(output.as_mut(), ECFlag::COMPRESSED)?;

        Ok(output)
    }

    pub fn negate(&mut self) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_pubkey_negate(self.ctx.ctx, &mut self.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn tweak_add(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_pubkey_tweak_add(self.ctx.ctx, &mut self.raw, tweak.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn tweak_mul(&mut self, tweak: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_ec_pubkey_tweak_mul(self.ctx.ctx, &mut self.raw, tweak.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn combine(ctx: &'a Context, ins: &[PublicKey]) -> Result<Self> {
        let mut key = Self::new(ctx);
        let keys = ins.iter().map(|v| &v.raw as *const _).collect::<Vec<_>>().as_ptr();
        let ret = unsafe {
            secp256k1_ec_pubkey_combine(ctx.ctx, &mut key.raw, keys, ins.len())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(key)
        }
    }
}
