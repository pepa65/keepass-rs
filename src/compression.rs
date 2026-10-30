use std::io::Read;
use std::io::Write;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as Flate2Compression;
use zeroize::Zeroizing;

pub trait Compression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
    fn decompress(&self, in_buffer: &[u8]) -> Result<Zeroizing<Vec<u8>>, std::io::Error>;
}

pub struct NoCompression;

impl Compression for NoCompression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
        Ok(in_buffer.to_vec().into())
    }
}

pub struct GZipCompression;

impl Compression for GZipCompression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut encoder = GzEncoder::new(&mut res, Flate2Compression::default());
        encoder.write_all(in_buffer)?;
        encoder.flush()?;
        encoder.finish()?;
        Ok(res)
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
        let mut decoder = GzDecoder::new(in_buffer);
        let mut out: Zeroizing<Vec<u8>> = Vec::with_capacity(in_buffer.len().saturating_mul(4)).into();
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            let n = match decoder.read(&mut *chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if out.capacity() - out.len() < n {
                let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + n).max(out.capacity() * 2)));
                bigger.extend_from_slice(&out);
                out = bigger; // old buffer wiped on drop
            }
            out.extend_from_slice(chunk.get(..n).unwrap_or_default());
        }
        Ok(out)
    }
}
