use hybrid_array::{
	Array as GenericArray,
	typenum::{U32, U64},
};

use cipher::{InvalidLength, KeyInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub(crate) mod ciphers;
pub(crate) mod kdf;

pub(crate) type Key256 = Zeroizing<GenericArray<u8, U32>>;
pub(crate) type Key512 = Zeroizing<GenericArray<u8, U64>>;

pub(crate) fn sha256_key(elements: &[&[u8]]) -> Key256 {
	Zeroizing::new(calculate_sha256(elements))
}

pub(crate) fn sha512_key(elements: &[&[u8]]) -> Key512 {
	Zeroizing::new(calculate_sha512(elements))
}

/// SHA-256 over `elements`, returned as a self-wiping Vec. The temporary
/// digest array is wiped before returning.
pub(crate) fn sha256_element(elements: &[&[u8]]) -> Zeroizing<Vec<u8>> {
	let mut digest = calculate_sha256(elements);
	let out = Zeroizing::new(digest.to_vec());
	digest.as_mut_slice().zeroize();
	out
}

pub(crate) fn calculate_hmac(elements: &[&[u8]], key: &[u8]) -> Result<Key256, InvalidLength> {
	type HmacSha256 = Hmac<Sha256>;
	let mut mac = HmacSha256::new_from_slice(key)?;

	for element in elements {
		mac.update(element);
	}

	let result = mac.finalize();
	Ok(Zeroizing::new(result.into_bytes()))
}

pub(crate) fn calculate_sha256(elements: &[&[u8]]) -> GenericArray<u8, U32> {
	let mut digest = Sha256::new();

	for element in elements {
		digest.update(element);
	}

	digest.finalize()
}

pub(crate) fn calculate_sha512(elements: &[&[u8]]) -> GenericArray<u8, U64> {
	let mut digest = Sha512::new();

	for element in elements {
		digest.update(element);
	}

	digest.finalize()
}

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptographyError {
	/// An invalid key length was provided
	#[error(transparent)]
	InvalidLength(#[from] InvalidLength),

	/// Data has invalid padding
	#[error(transparent)]
	InvalidPadding(#[from] cipher::block_padding::Error),

	/// Errors related to the Argon2 key derivation function
	#[error(transparent)]
	Argon2(#[from] argon2::Error),
}
