use std::fmt;

#[derive(Debug, Clone)]
pub struct YaraError {
    pub msg: String,
    pub line: usize,
}

impl YaraError {
    pub fn new(msg: impl Into<String>, line: usize) -> Self {
        YaraError { msg: msg.into(), line }
    }
}

impl fmt::Display for YaraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for YaraError {}

pub type YResult<T> = Result<T, YaraError>;

pub fn err<T>(msg: impl Into<String>, line: usize) -> YResult<T> {
    Err(YaraError::new(msg, line))
}
