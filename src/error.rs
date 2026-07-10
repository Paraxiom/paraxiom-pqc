#[derive(Debug, thiserror::Error)]
pub enum PqcError {
    #[error("key generation failed: {0}")]
    KeyGen(String),

    #[error("encapsulation failed: {0}")]
    Encapsulate(String),

    #[error("decapsulation failed: {0}")]
    Decapsulate(String),

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("verification failed: {0}")]
    Verify(String),

    #[error("invalid key size: got {got}, expected {expected}")]
    InvalidKeySize { got: usize, expected: usize },

    #[error("invalid signature size: got {got}, expected {expected}")]
    InvalidSignatureSize { got: usize, expected: usize },
}
