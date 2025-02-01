use std::borrow::Cow;

use serde::{Deserialize, Serialize};

pub mod core;
pub mod encoding;
pub mod keygen;
pub mod serialize;
pub mod traits;

pub use crate::core::*;
pub use encoding::*;
pub use keygen::*;
pub use traits::*;

pub use curv::arithmetic::BigInt;

/// Main struct onto which most operations are added.
pub struct Paillier;

pub struct JoyeLibert;

/// should add y for jl? 
/// Keypair from which encryption and decryption keys can be derived.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Keypair {
    #[serde(with = "crate::serialize::bigint")]
    pub p: BigInt, // TODO[Morten] okay to make non-public?

    #[serde(with = "crate::serialize::bigint")]
    pub q: BigInt, // TODO[Morten] okay to make non-public?

    #[serde(with = "crate::serialize::bigint")]
    pub y: BigInt, 

    // #[serde(with = "crate::serialize::bigint")]
    pub k: usize, //TODO: is usize a proper type here?  
}

// /// Set default value for keygen
// /// p, q, => 3
// /// y => 5
// /// k = 3072: N-bit for jl enc.
// impl Default for Keypair {
//     fn default() -> Self {
//         Self {
//             p: BigInt::from(3),
//             q: BigInt::from(3),
//             y: BigInt::from(5),
//             k: BigInt::from(5),
//         }
//     }
// }


// /// Public encryption key with no precomputed values.
// ///
// /// Used e.g. for serialization of `EncryptionKey`.
// #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
// pub struct MinimalEncryptionKey {
//     #[serde(with = "crate::serialize::bigint")]
//     pub n: BigInt,
// }

// /// Private decryption key with no precomputed values.
// ///
// /// Used e.g. for serialization of `DecryptionKey`.
// #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
// pub struct MinimalDecryptionKey {
//     #[serde(with = "crate::serialize::bigint")]
//     pub p: BigInt,

//     #[serde(with = "crate::serialize::bigint")]
//     pub q: BigInt,
// }

/// Public encryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    pub n: BigInt,  // the modulus
    pub y: BigInt,
    pub k: usize,
}

/// Private decryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionKey {
    pub p: BigInt, // n = p*q
    pub q: BigInt,
    pub y: BigInt,
    pub k: usize, // msg bit size
}

/// Unencrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawPlaintext<'b>(pub Cow<'b, BigInt>);

/// Encrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawCiphertext<'b>(pub Cow<'b, BigInt>);
