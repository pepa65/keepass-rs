use aes::Aes256;
#[cfg(feature = "save_kdbx4")]
use cipher::BlockModeEncrypt;
use cipher::{block_padding::Pkcs7, BlockModeDecrypt};
use hybrid_array::Array as GenericArray;
use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa20,
};
use zeroize::Zeroizing;

use crate::crypt::{sha256_key, CryptographyError};

pub(crate) trait Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptographyError>;

    #[cfg(feature = "save_kdbx4")]
    /// The number of bytes expected by the cipher as an initialization vector.
    fn iv_size() -> usize
    where
        Self: Sized;

    #[cfg(feature = "save_kdbx4")]
    /// The number of bytes expected by the cipher as a key.
    fn key_size() -> usize
    where
        Self: Sized;
}

#[cfg(feature = "save_kdbx4")]
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
pub(crate) struct AES256Cipher {
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
}

impl AES256Cipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(AES256Cipher {
            key: Vec::from(key).into(),
            iv: Vec::from(iv).into(),
        })
    }
}

impl Cipher for AES256Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = Aes256CbcEncryptor::new_from_slices(&self.key, &self.iv)?;

        let ciphertext = cipher.encrypt_padded_vec::<Pkcs7>(plaintext);

        Ok(ciphertext)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        let mut out = Zeroizing::new(vec![0; ciphertext.len()]);

        let cipher = Aes256CbcDecryptor::new_from_slices(&self.key, &self.iv)?;

        let len = cipher
            .decrypt_padded_b2b::<Pkcs7>(ciphertext, out.as_mut_slice())?
            .len();

        out.truncate(len);

        Ok(out)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        16
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

#[cfg(feature = "save_kdbx4")]
type TwofishCbcEncryptor = cbc::Encryptor<twofish::Twofish>;
type TwofishCbcDecryptor = cbc::Decryptor<twofish::Twofish>;
pub(crate) struct TwofishCipher {
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
}

impl TwofishCipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(TwofishCipher {
            key: Zeroizing::new(Vec::from(key)),
            iv: Zeroizing::new(Vec::from(iv)),
        })
    }
}

impl Cipher for TwofishCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = TwofishCbcEncryptor::new_from_slices(&self.key, &self.iv)?;

        let ciphertext = cipher.encrypt_padded_vec::<twofish::cipher::block_padding::Pkcs7>(plaintext);

        Ok(ciphertext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        let cipher = TwofishCbcDecryptor::new_from_slices(&self.key, &self.iv)?;

        let mut buf = Zeroizing::new(ciphertext.to_vec());
        cipher.decrypt_padded::<twofish::cipher::block_padding::Pkcs7>(buf.as_mut_slice())?;
        Ok(buf)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        16
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct Salsa20Cipher {
    cipher: salsa20::Salsa20,
}

impl Salsa20Cipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptographyError> {
        let key = sha256_key(&[key]);
        let iv = GenericArray::from([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);

        Ok(Salsa20Cipher {
            cipher: Salsa20::new(&key, &iv),
        })
    }
}

impl Cipher for Salsa20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(plaintext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        let mut buffer = Zeroizing::new(Vec::from(ciphertext));
        self.cipher.apply_keystream(buffer.as_mut_slice());
        Ok(buffer)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        // or 16
        32
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct ChaCha20Cipher {
    cipher: chacha20::ChaCha20,
}

impl ChaCha20Cipher {
    /// Create as an inner cipher by splitting up a SHA512 hash
    #[allow(clippy::indexing_slicing)] // Slicing is safe because SHA512 output is always 64 bytes
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptographyError> {
        let iv = crate::crypt::sha512_key(&[key]);

        // borrow the key and nonce straight out of the wiped hash instead of copying them
        // into named arrays
        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new_from_slices(&iv[0..32], &iv[32..44])?,
        })
    }

    /// Create as an outer cipher by separately-specified key and iv
    pub(crate) fn new_key_iv(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new_from_slices(key, iv)?,
        })
    }
}

impl Cipher for ChaCha20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(plaintext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        let mut buffer = Zeroizing::new(Vec::from(ciphertext));
        self.cipher.apply_keystream(buffer.as_mut_slice());
        Ok(buffer)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        12
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct PlainCipher;
impl PlainCipher {
    pub(crate) fn new(_: &[u8]) -> Result<Self, CryptographyError> {
        Ok(PlainCipher)
    }
}
impl Cipher for PlainCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        Ok(Vec::from(plaintext))
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        Ok(Vec::from(ciphertext).into())
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        1
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        1
    }
}
