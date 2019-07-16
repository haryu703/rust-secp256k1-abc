use failure;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, failure::Fail)]
pub enum Error {
    #[fail(display = "internal secp256k1 error")]
    SysError,
}
