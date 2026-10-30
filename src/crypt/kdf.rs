use std::convert::TryInto;

use aes::Aes256;
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{
	Array as GenericArray,
	typenum::{U16, U32},
};
use zeroize::Zeroizing;

use super::{CryptographyError, Key256};

pub(crate) trait Kdf {
	fn transform_key(&self, composite_key: &GenericArray<u8, U32>) -> Result<Key256, CryptographyError>;
}

pub struct AesKdf {
	pub seed: Vec<u8>,
	pub rounds: u64,
}

impl Kdf for AesKdf {
	#[allow(clippy::indexing_slicing)] // Slicing is safe because composite_key is always 32 bytes
	fn transform_key(&self, composite_key: &GenericArray<u8, U32>) -> Result<Key256, CryptographyError> {
		let seed_arr = self.seed.as_slice().try_into().map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
		let cipher = Aes256::new(&seed_arr);
		let mut block1: Zeroizing<GenericArray<u8, U16>> =
			Zeroizing::new(composite_key[..16].try_into().map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?);
		let mut block2: Zeroizing<GenericArray<u8, U16>> =
			Zeroizing::new(composite_key[16..].try_into().map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?);
		for _ in 0..self.rounds {
			cipher.encrypt_block(&mut block1);
			cipher.encrypt_block(&mut block2);
		}
		Ok(super::sha256_key(&[block1.as_slice(), block2.as_slice()]))
	}
}

pub struct Argon2Kdf {
	pub memory: u64,
	pub salt: Vec<u8>,
	pub iterations: u64,
	pub parallelism: u32,
	pub version: argon2::Version,
	pub variant: argon2::Variant,
}

impl Kdf for Argon2Kdf {
	fn transform_key(&self, composite_key: &GenericArray<u8, U32>) -> Result<Key256, CryptographyError> {
		let config = argon2::Config {
			thread_mode: argon2::ThreadMode::Parallel,
			ad: &[],
			hash_length: 32,
			lanes: self.parallelism,
			mem_cost: (self.memory / 1024) as u32,
			secret: &[],
			time_cost: self.iterations as u32,
			variant: self.variant,
			version: self.version,
		};

		let key = Zeroizing::new(argon2::hash_raw(composite_key, &self.salt, &config)?);
		if key.len() != 32 {
			return Err(CryptographyError::InvalidLength(cipher::InvalidLength));
		}
		let mut out: Key256 = GenericArray::default().into();
		out.as_mut_slice().copy_from_slice(&key);
		Ok(out)
	}
}

#[cfg(test)]
mod tests {
	use argon2::{Config, ThreadMode, Variant, Version, hash_raw};
	use hybrid_array::{Array as GenericArray, typenum::U32};

	use super::{Argon2Kdf, Kdf};

	#[test]
	fn argon2_memory_is_interpreted_as_bytes() {
		let composite_key = GenericArray::<u8, U32>::from([7_u8; 32]);
		let salt = vec![9_u8; 32];
		let kdf = Argon2Kdf {
			memory: 64 * 1024,
			salt: salt.clone(),
			iterations: 1,
			parallelism: 1,
			version: Version::Version13,
			variant: Variant::Argon2id,
		};

		let expected = hash_raw(
			&composite_key,
			&salt,
			&Config {
				thread_mode: ThreadMode::Parallel,
				ad: &[],
				hash_length: 32,
				lanes: 1,
				mem_cost: 64,
				secret: &[],
				time_cost: 1,
				variant: Variant::Argon2id,
				version: Version::Version13,
			},
		)
		.expect("argon2 test vector should derive successfully");

		let actual = kdf.transform_key(&composite_key).expect("argon2 kdf should derive successfully");

		assert_eq!(actual.as_slice(), expected.as_slice());
	}
}
