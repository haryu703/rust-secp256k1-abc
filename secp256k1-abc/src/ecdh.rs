use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, Error};

pub fn ecdh(ctx: &Context, pubkey: &PublicKey, privkey: &PrivateKey) -> Result<[u8; 32]> {
    let mut output = [0; 32];
    let ret = unsafe {
        secp256k1_ecdh(ctx.ctx, output.as_mut_ptr(), &pubkey.raw, privkey.raw.as_ptr())
    };
    if ret == 0 {
        Err(Error::SysError)
    } else {
        Ok(output)
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;
    use super::*;
    use super::super::ContextFlag;
    use sha2::{ Sha256, Digest };

    // Use secure random numbers for non-test key generation
    use rand::Rng;

    #[test]
    fn test_api() -> Result<()> {
        let ctx = Context::new(ContextFlag::SIGN);
        let priv1 = PrivateKey::from_array(&ctx, hex!("0000000000000000000000000000000000000000000000000000000000000001"));
        let pub1 = PublicKey::try_from(&priv1)?;

        for _ in 0..100 {
            let r = rand::thread_rng().gen();

            let priv2 = PrivateKey::from_array(&ctx, r);
            let pub2 = PublicKey::try_from(&priv2)?;

            let ret = ecdh(&ctx, &pub1, &priv2)?;

            let ser_pub2 = pub2.serialize_compressed()?;
            let sha = Sha256::default().chain(ser_pub2.as_ref()).result();
        }

        Ok(())
    }
}
