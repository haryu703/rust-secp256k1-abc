use super::Result;

pub fn convert_return<T>(ret: ::std::os::raw::c_int, t: T) -> Result<T> {
    if ret == 1 {
        Ok(t)
    } else {
        Err(ret)
    }
}
