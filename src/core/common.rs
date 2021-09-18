use std::{fmt::Display, io::{Write, stdout}};

#[derive(Debug, Clone)]
pub enum ErrorType {
    Runtime,
    Container,
}

impl std::fmt::Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &ErrorType::Container => write!(f, "container"),
            &ErrorType::Runtime => write!(f, "runtime"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub msg: String,
    pub err_type: ErrorType,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ERROR: type {} - {}", self.err_type, self.msg)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// hepler methods

pub fn exit(code: i32) -> ! {
    std::process::exit(code);
}

pub fn exit_msg<T: Display>(code: i32, msg: T) -> ! {
    let _ = stdout().write_all(msg.to_string().as_bytes());
    std::process::exit(code);
}