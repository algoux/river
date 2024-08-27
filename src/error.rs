pub enum Error {
    E(String),
}

pub type RResult<T> = Result<T, Error>;

impl Error {
    pub fn to_string(&self) -> String {
        match *self {
            Error::E(ref s) => format!("{}", s),
        }
    }
}
