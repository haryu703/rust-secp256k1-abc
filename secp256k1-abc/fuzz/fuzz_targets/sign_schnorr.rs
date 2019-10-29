#![no_main]
use std::convert::TryFrom;
use std::convert::TryInto;
use libfuzzer_sys::fuzz_target;
use secp256k1_abc::*;

fuzz_target!(|data: &[u8]| {
    let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);

    if data.len() < 32 {
        return;
    }
    let msg: &[u8; 32] = &data[0..32].try_into().unwrap();

    let privkey = PrivateKey::from_array(&ctx, *msg);

    if let Ok(pubkey) = PublicKey::try_from(&privkey) {
        let sig = schnorr::sign(&ctx, msg, &privkey).unwrap();
        assert!(schnorr::verify(&ctx, &sig, msg, &pubkey).is_ok());
    }
});
