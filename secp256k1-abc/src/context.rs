use std::str::Utf8Error;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use secp256k1_abc_sys::*;
use super::{Result, Error};

bitflags! {
    pub struct ContextFlag: u32 {
        const VERIFY = SECP256K1_CONTEXT_VERIFY;
        const SIGN = SECP256K1_CONTEXT_SIGN;
        const NONE = SECP256K1_CONTEXT_NONE;
    }
}

pub type IllegalClosure<'a> = &'a mut dyn FnMut(std::result::Result<&str, Utf8Error>);

extern "C" fn illegal_callback(message: *const c_char, data: *mut c_void) {
    if data.is_null() {
        return;
    }

    let closure = unsafe {
        &mut *(data as *mut IllegalClosure)
    };
    let message = unsafe { CStr::from_ptr(message) }.to_str();
    (*closure)(message);
}

pub type ErrorClosure<'a> = &'a mut dyn FnMut(std::result::Result<&str, Utf8Error>);

extern "C" fn error_callback(message: *const c_char, data: *mut c_void) {
    if data.is_null() {
        return;
    }

    let closure = unsafe {
        &mut *(data as *mut ErrorClosure)
    };
    let message = unsafe { CStr::from_ptr(message) }.to_str();
    (*closure)(message);
}

pub struct Context<'a> {
    pub(crate) ctx: *mut secp256k1_context,
    illegal_closure: Option<IllegalClosure<'a>>,
    error_closure: Option<ErrorClosure<'a>>,
}

impl<'a> Clone for Context<'a> {
    fn clone(&self) -> Self {
        Context {
            ctx: unsafe { secp256k1_context_clone(self.ctx) },
            illegal_closure: None,
            error_closure: None,
        }
    }
}

impl<'a> Drop for Context<'a> {
    fn drop(&mut self) {
        unsafe {
            secp256k1_context_destroy(self.ctx);
            self.set_illegal_callback(None, std::ptr::null());
            self.set_error_callback(None, std::ptr::null());
        };
    }
}

impl<'a> Context<'a> {
    pub fn new(flags: ContextFlag) -> Self {
        Context {
            ctx: unsafe { secp256k1_context_create(flags.bits) },
            illegal_closure: None,
            error_closure: None,
        }
    }

    pub fn randomize(&mut self, seed: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_context_randomize(self.ctx, seed.as_ptr())
        };
        if ret == 0 {
            Err(Error::SysError)
        } else {
            Ok(())
        }
    }

    pub unsafe fn set_illegal_callback(
        &self,
        fun: Option<unsafe extern "C" fn(message: *const c_char, data: *mut c_void)>,
        data: *const c_void,
    ) {
        secp256k1_abc_sys::secp256k1_context_set_illegal_callback(self.ctx, fun, data)
    }

    pub unsafe fn set_error_callback(
        &self,
        fun: Option<unsafe extern "C" fn(message: *const c_char, data: *mut c_void)>,
        data: *const c_void,
    ) {
        secp256k1_abc_sys::secp256k1_context_set_error_callback(self.ctx, fun, data)
    }

    pub fn set_illegal_closure(&mut self, cb: IllegalClosure<'a>) {
        self.illegal_closure = Some(cb);
        let p = &mut self.illegal_closure as *mut _ as *mut c_void;
        unsafe {
            self.set_illegal_callback(Some(illegal_callback), p)
        }
    }

    pub fn set_error_closure(&mut self, cb: ErrorClosure<'a>) {
        self.error_closure = Some(cb);
        let p = &mut self.error_closure as *mut _ as *mut c_void;
        unsafe {
            self.set_error_callback(Some(error_callback), p)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::*;
    use std::convert::TryFrom;
    use std::sync::atomic::{AtomicI32, Ordering};

    #[test]
    fn illegal_callback() {
        let ecount = AtomicI32::new(0);
        let mut cb = |msg: std::result::Result<&str, Utf8Error>| {
            assert_eq!(msg.is_ok(), true);
            ecount.fetch_add(1, Ordering::Relaxed);
        };

        let mut verify = Context::new(ContextFlag::VERIFY);

        let ref_cb = &mut cb as IllegalClosure;

        verify.set_illegal_closure(ref_cb);
        let privkey = PrivateKey::from_array(&verify, hex!("d7f8f06b9da388bfe1f56c9630090e9f24a48dd1a8d1d5ed059b48117d69f88c"));
        let pubkey = PublicKey::try_from(&privkey);

        assert_eq!(pubkey.is_err(), true);
        assert_eq!(ecount.load(Ordering::Relaxed), 1);
    }
}
