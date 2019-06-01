use secp256k1_abc_sys::*;
use super::context::Context;
use super::utils::convert_return;
use super::Result;

pub struct MultiSet<'a> {
    raw: secp256k1_multiset,
    ctx: &'a Context,
}

impl<'a> MultiSet<'a> {
    pub fn new(ctx: &'a Context) -> Result<Self> {
        let mut multiset = MultiSet {
            raw: secp256k1_multiset {
                _bindgen_opaque_blob: [0; 96],
            },
            ctx,
        };
        let ret = unsafe {
            secp256k1_multiset_init(ctx.ctx, &mut multiset.raw)
        };
        convert_return(ret, multiset)
    }

    pub fn add(&mut self, input: &[u8]) -> Result<()> {
        let ret = unsafe {
            secp256k1_multiset_add(self.ctx.ctx, &mut self.raw, input.as_ptr(), input.len())
        };
        convert_return(ret, ())
    }

    pub fn remove(&mut self, input: &[u8]) -> Result<()> {
        let ret = unsafe {
            secp256k1_multiset_remove(self.ctx.ctx, &mut self.raw, input.as_ptr(), input.len())
        };
        convert_return(ret, ())
    }

    pub fn combine(&mut self, input: MultiSet) -> Result<()> {
        let ret = unsafe {
            secp256k1_multiset_combine(self.ctx.ctx, &mut self.raw, &input.raw)
        };
        convert_return(ret, ())
    }

    pub fn finalize(&self) -> Result<[u8; 32]> {
        let mut hash = [0; 32];
        let ret = unsafe {
            secp256k1_multiset_finalize(self.ctx.ctx, hash.as_mut_ptr(), &self.raw)
        };
        convert_return(ret, hash)
    }
}
