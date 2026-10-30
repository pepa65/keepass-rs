mod dump;
mod parse;

use zeroize::Zeroizing;

use crate::{
	config::{CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
	format::variant_dictionary::VariantDictionary,
};

pub(crate) use crate::format::kdbx4::dump::dump_kdbx4;
pub(crate) use crate::format::kdbx4::parse::parse_kdbx4;

pub use crate::format::kdbx4::parse::Kdbx4OpenError;

/// Size for a master seed in bytes
pub const HEADER_MASTER_SEED_SIZE: usize = 32;

/// Header entry denoting the end of the header
pub const HEADER_END: u8 = 0;
/// Header entry denoting a comment
pub const HEADER_COMMENT: u8 = 1;
/// A UUID specifying which cipher suite should be used to encrypt the payload
pub const HEADER_OUTER_ENCRYPTION_ID: u8 = 2;
/// First byte determines compression of payload
pub const HEADER_COMPRESSION_ID: u8 = 3;
/// Master seed for deriving the master key
pub const HEADER_MASTER_SEED: u8 = 4;
/// Initialization Vector for decrypting the payload
pub const HEADER_ENCRYPTION_IV: u8 = 7;
/// Parameters for the key derivation function
pub const HEADER_KDF_PARAMS: u8 = 11;
/// Custom data of plugins/ports.
pub const HEADER_PUBLIC_CUSTOM_DATA: u8 = 12;

/// Inner header entry denoting the end of the inner header
pub const INNER_HEADER_END: u8 = 0x00;
/// Inner header entry denoting the UUID of the inner cipher
pub const INNER_HEADER_RANDOM_STREAM_ID: u8 = 0x01;
/// Inner header entry denoting the key of the inner cipher
pub const INNER_HEADER_RANDOM_STREAM_KEY: u8 = 0x02;
/// Inner header entry denoting a binary attachment
pub const INNER_HEADER_BINARY_ATTACHMENTS: u8 = 0x03;

struct KDBX4OuterHeader {
	outer_cipher_config: OuterCipherConfig,
	compression_config: CompressionConfig,
	master_seed: Vec<u8>,
	outer_iv: Vec<u8>,
	kdf_config: KdfConfig,
	kdf_seed: Vec<u8>,
	public_custom_data: Option<VariantDictionary>,
}

struct KDBX4InnerHeader {
	inner_random_stream: InnerCipherConfig,
	inner_random_stream_key: Zeroizing<Vec<u8>>,
}
