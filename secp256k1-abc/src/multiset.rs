use secp256k1_abc_sys::*;
use super::context::Context;
use super::{Result, Error};

pub struct MultiSet<'a, 'b> {
    raw: secp256k1_multiset,
    ctx: &'a Context<'b>,
}

impl<'a, 'b> MultiSet<'a, 'b> {
    pub fn new(ctx: &'a Context<'b>) -> Result<Self> {
        let mut multiset = MultiSet {
            raw: secp256k1_multiset {
                _bindgen_opaque_blob: [0; 96],
            },
            ctx,
        };
        let ret = unsafe {
            secp256k1_multiset_init(ctx.ctx, &mut multiset.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(multiset)
        }
    }

    pub fn add(&mut self, input: &[u8]) -> Result<()> {
        let ret = unsafe {
            secp256k1_multiset_add(self.ctx.ctx, &mut self.raw, input.as_ptr(), input.len())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn remove(&mut self, input: &[u8]) -> Result<()> {
        let ret = unsafe {
            secp256k1_multiset_remove(self.ctx.ctx, &mut self.raw, input.as_ptr(), input.len())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn combine(&mut self, input: MultiSet) -> Result<()> {
        let ret = unsafe {
            secp256k1_multiset_combine(self.ctx.ctx, &mut self.raw, &input.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub fn finalize(&self) -> Result<[u8; 32]> {
        let mut hash = [0; 32];
        let ret = unsafe {
            secp256k1_multiset_finalize(self.ctx.ctx, hash.as_mut_ptr(), &self.raw)
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(hash)
        }
    }
}
