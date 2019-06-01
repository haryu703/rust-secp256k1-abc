// use std::ffi::CStr;
use secp256k1_abc_sys::*;
use super::utils::convert_return;
use super::Result;

bitflags! {
    pub struct ContextFlag: u32 {
        const VERIFY = SECP256K1_CONTEXT_VERIFY;
        const SIGN = SECP256K1_CONTEXT_SIGN;
        const NONE = SECP256K1_CONTEXT_NONE;
    }
}

// extern "C" fn illegal_callback(message: *const ::std::os::raw::c_char, data: *mut ::std::os::raw::c_void) {
//     let closure: &mut Box<FnMut(&CStr)> = unsafe { std::mem::transmute(data) };
//     closure(unsafe { CStr::from_ptr(message) });
// }

// extern "C" fn error_callback(message: *const ::std::os::raw::c_char, data: *mut ::std::os::raw::c_void) {
//     let closure: &mut Box<FnMut(&CStr)> = unsafe { std::mem::transmute(data) };
//     closure(unsafe { CStr::from_ptr(message) });
// }

pub struct Context {
    pub(crate) ctx: *mut secp256k1_context,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Context {
            ctx: unsafe { secp256k1_context_clone(self.ctx) },
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { secp256k1_context_destroy(self.ctx) };
    }
}

impl Context {
    pub fn new(flags: ContextFlag) -> Self {
        Context {
            ctx: unsafe { secp256k1_context_create(flags.bits) },
        }
    }

    pub fn randomize(&mut self, seed: &[u8; 32]) -> Result<()> {
        let ret = unsafe {
            secp256k1_context_randomize(self.ctx, seed.as_ptr())
        };
        convert_return(ret, ())
    }

    // pub fn set_illegal_callback<F>(&mut self, cb: F)
    //     where F: FnMut(&CStr) {
    //     let cb = Box::new(Box::new(cb));
    //     unsafe {
    //         secp256k1_abc_sys::secp256k1_context_set_illegal_callback(self.context, Some(illegal_callback), Box::into_raw(cb) as *mut _)
    //     }
    // }

    // pub fn set_error_callback<F>(&mut self, cb: F)
    //     where F: FnMut(&CStr) {
    //     let cb = Box::new(Box::new(cb));
    //     unsafe {
    //         secp256k1_abc_sys::secp256k1_context_set_error_callback(self.context, Some(error_callback), Box::into_raw(cb) as *mut _)
    //     }
    // }
}
