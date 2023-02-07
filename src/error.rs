#[derive(thiserror::Error, Debug)]
#[error("Timeout error")]
pub struct TimeoutError;
impl From<TimeoutError> for std::io::Error {
    fn from(value: TimeoutError) -> Self {
        std::io::Error::new(std::io::ErrorKind::TimedOut, value)
    }
}
