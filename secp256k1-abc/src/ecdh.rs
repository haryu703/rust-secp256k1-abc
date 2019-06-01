use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::Result;
use super::utils::convert_return;

pub fn ecdh(ctx: &Context, pubkey: &PublicKey, privkey: PrivateKey) -> Result<[u8; 32]> {
    let mut output = [0; 32];
    let ret = unsafe {
        secp256k1_ecdh(ctx.ctx, output.as_mut_ptr(), &pubkey.raw, privkey.raw.as_ptr())
    };
    convert_return(ret, output)
}
