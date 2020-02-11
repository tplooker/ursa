#[cfg(feature = "sha2")]
pub use sha2;
#[cfg(feature = "sha3")]
pub use sha3;

#[cfg(feature = "sha2")]
pub use sha2::Digest;

#[cfg(feature = "blake2")]
pub mod blake2;
#[cfg(feature = "blake2")]
pub use blake2::digest::{Input, VariableOutput};

