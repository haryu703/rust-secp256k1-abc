use std::ptr;
use std::os::raw::c_void;
use secp256k1_abc_sys::*;
use super::context::Context;
use super::public_key::PublicKey;
use super::private_key::PrivateKey;
use super::{Result, Error};
use super::nonce_function::{nonce_function, NonceClosure};

pub fn verify(ctx: &Context, sig: &[u8; 64], msg: &[u8; 32], pubkey: &PublicKey) -> Result<()> {
    let ret = unsafe {
        secp256k1_schnorr_verify(ctx.ctx, sig.as_ptr(), msg.as_ptr(), &pubkey.raw)
    };
    if ret == 0 {
        Err(Error::SysError)
    } else {
        Ok(())
    }
}

pub fn sign_with_nonce_closure<F>(ctx: &Context, msg: &[u8; 32], seckey: &PrivateKey, mut nonce_closure: F) -> Result<[u8; 64]>
    where F: FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32 {
    let mut sig = [0; 64];
    let mut obj: NonceClosure = &mut nonce_closure;
    let data = &mut obj as *const _ as *const c_void;
    let ret = unsafe {
        secp256k1_schnorr_sign(
            ctx.ctx,
            sig.as_mut_ptr(),
            msg.as_ptr(),
            seckey.key.as_ptr(),
            Some(nonce_function),
            data,
        )
    };
    if ret == 0 {
        Err(Error::SysError)
    } else {
        Ok(sig)
    }
}

pub fn sign(ctx: &Context, msg: &[u8; 32], seckey: &PrivateKey) -> Result<[u8; 64]> {
    let mut sig = [0; 64];
    let ret = unsafe {
        secp256k1_schnorr_sign(ctx.ctx, sig.as_mut_ptr(), msg.as_ptr(), seckey.key.as_ptr(), None, ptr::null())
    };
    if ret == 0 {
        Err(Error::SysError)
    } else {
        Ok(sig)
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;
    use super::*;
    use super::super::ContextFlag;

    // reference: https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/secp256k1/src/modules/schnorr/tests_impl.h

    #[test]
    fn test_sign_verify() -> Result<()> {
        let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);
        let msg = hex!("4f1379111cc4350a52280fca4f21673ec8db83edaa9be0731fd9fe6aa4d63c5e");

        let privkey = PrivateKey::from_array(&ctx, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::try_from(&privkey)?;

        let sig = sign(&ctx, &msg, &privkey)?;
        assert!(verify(&ctx, &sig, &msg, &pubkey).is_ok());

        Ok(())
    }

    #[test]
    fn test_verify() -> Result<()> {
        let ctx = Context::new(ContextFlag::VERIFY);
        let test_vec = [
            (
                hex!("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                hex!("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05")
            ),
            (
                hex!("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
            ),
            (
                hex!("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
                hex!("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
                hex!("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380")
            ),
            (
                hex!("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
                hex!("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
                hex!("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D")
            ),
            (
                hex!("031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F"),
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                hex!("52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187")
            ),
        ];

        for (pk, msg, sig) in test_vec.iter() {
            let pubkey = PublicKey::parse(&ctx, pk)?;
            assert!(verify(&ctx, sig, msg, &pubkey).is_ok());
        }

        Ok(())
    }

    #[test]
    fn test_verify_fail() -> Result<()> {
        let ctx = Context::new(ContextFlag::VERIFY);
        let test_vec = [
            (
                hex!("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7")
            ),
            (
                hex!("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
                hex!("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
                hex!("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC")
            ),
            (
                hex!("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                hex!("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C")
            ),
            (
                hex!("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
            ),
            (
                hex!("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D8C3428869A663ED1E954705B020CBB3E7BB6AC31965B9EA4C73E227B17C5AF5A")
            ),
            (
                hex!("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
            ),
            (
                hex!("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
            ),
            (
                hex!("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                hex!("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
                hex!("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            ),
        ];

        for (pk, msg, sig) in test_vec.iter() {
            let pubkey = PublicKey::parse(&ctx, pk)?;
            assert!(verify(&ctx, sig, msg, &pubkey).is_err());
        }

        Ok(())
    }

    #[test]
    fn test_custom_nonce() -> Result<()> {
        let ctx = Context::new(ContextFlag::SIGN | ContextFlag::VERIFY);
        let msg = hex!("4f1379111cc4350a52280fca4f21673ec8db83edaa9be0731fd9fe6aa4d63c5e");

        let privkey = PrivateKey::from_array(&ctx, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::try_from(&privkey)?;

        let sig = sign_with_nonce_closure(&ctx, &msg, &privkey, |nonce, msg, key, algo, attempt| {
            assert!(nonce.is_some());
            assert!(msg.is_some());
            assert!(key.is_some());
            assert!(algo.is_some());
            assert!(attempt == 0);
            1
        })?;
        assert!(verify(&ctx, &sig, &msg, &pubkey).is_ok());

        Ok(())
    }
}
