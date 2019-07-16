use std::convert::TryInto;
use std::os::raw::{c_void, c_uchar, c_uint, c_int};

pub use secp256k1_abc_sys::secp256k1_nonce_function_rfc6979 as rfc6979;
pub use secp256k1_abc_sys::secp256k1_nonce_function_default as default;

macro_rules! ptr_to_mut_slice {
    ($p:expr, $len:expr) => {
        if $p.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts_mut($p, $len) }.try_into().unwrap())
        }
    };
}

macro_rules! ptr_to_slice {
    ($p:expr, $len:expr) => {
        if $p.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts($p, $len) }.try_into().unwrap())
        }
    };
}

pub type NonceClosure<'a> = &'a mut FnMut(Option<&mut [u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 32]>, Option<&[u8; 16]>, u32) -> i32;

pub extern "C" fn nonce_function(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
    attempt: c_uint,
) -> c_int {
    if data.is_null() {
        return 0;
    }

    let closure = unsafe {
        &mut *(data as *mut NonceClosure)
    };
    let nonce = ptr_to_mut_slice!(nonce32, 32);
    let msg = ptr_to_slice!(msg32, 32);
    let key = ptr_to_slice!(key32, 32);
    let algo = ptr_to_slice!(algo16, 16);
    closure(nonce, msg, key, algo, attempt)
}
