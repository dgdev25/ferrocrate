use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use thiserror::Error;

const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionFormat {
    None,
    Gzip,
    Zstd,
}

#[derive(Debug, Error)]
pub enum LayerCompressionError {
    #[error("failed to open layer tarball {0}")]
    Open(String, #[source] io::Error),
    #[error("failed to read layer tarball {0}")]
    Read(String, #[source] io::Error),
    #[error("failed to decompress gzip layer")]
    Gzip(#[source] io::Error),
    #[error("failed to decompress zstd layer")]
    Zstd(#[source] io::Error),
}

pub fn detect_format(bytes: &[u8]) -> CompressionFormat {
    if bytes.len() >= 4 && bytes[..4] == ZSTD_MAGIC {
        CompressionFormat::Zstd
    } else if bytes.len() >= 2 && bytes[..2] == GZIP_MAGIC {
        CompressionFormat::Gzip
    } else {
        CompressionFormat::None
    }
}

/// Open a layer tarball and return a reader that yields decompressed tar bytes.
pub fn open_decompressed_layer_reader(
    layer_path: &Path,
) -> Result<Box<dyn Read>, LayerCompressionError> {
    let mut file = File::open(layer_path)
        .map_err(|err| LayerCompressionError::Open(layer_path.display().to_string(), err))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| LayerCompressionError::Read(layer_path.display().to_string(), err))?;

    decompress_bytes_to_reader(bytes)
}

pub fn decompress_bytes_to_reader(bytes: Vec<u8>) -> Result<Box<dyn Read>, LayerCompressionError> {
    match detect_format(&bytes) {
        CompressionFormat::None => Ok(Box::new(Cursor::new(bytes))),
        CompressionFormat::Gzip => {
            let mut out = Vec::new();
            let mut decoder = GzDecoder::new(Cursor::new(bytes));
            decoder
                .read_to_end(&mut out)
                .map_err(LayerCompressionError::Gzip)?;
            Ok(Box::new(Cursor::new(out)))
        }
        CompressionFormat::Zstd => {
            let out = zstd::stream::decode_all(Cursor::new(bytes))
                .map_err(LayerCompressionError::Zstd)?;
            Ok(Box::new(Cursor::new(out)))
        }
    }
}

pub fn compress_bytes_gzip(bytes: &[u8]) -> Result<Vec<u8>, LayerCompressionError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .map_err(LayerCompressionError::Gzip)?;
    encoder.finish().map_err(LayerCompressionError::Gzip)
}

pub fn compress_bytes_zstd(bytes: &[u8]) -> Result<Vec<u8>, LayerCompressionError> {
    zstd::stream::encode_all(bytes, 0).map_err(LayerCompressionError::Zstd)
}

#[cfg(test)]
mod tests {
    use super::{
        compress_bytes_gzip, compress_bytes_zstd, decompress_bytes_to_reader, detect_format,
        CompressionFormat,
    };
    use std::io::Read;

    #[test]
    fn detects_gzip_and_zstd_magic() {
        assert_eq!(detect_format(&[0x1F, 0x8B, 0x08]), CompressionFormat::Gzip);
        assert_eq!(
            detect_format(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]),
            CompressionFormat::Zstd
        );
        assert_eq!(detect_format(b"plain"), CompressionFormat::None);
    }

    #[test]
    fn decompresses_gzip_bytes() {
        let compressed = compress_bytes_gzip(b"hello-gzip").expect("compress gzip");

        let mut reader = decompress_bytes_to_reader(compressed).expect("gzip decompress");
        let mut out = String::new();
        reader.read_to_string(&mut out).expect("read output");

        assert_eq!(out, "hello-gzip");
    }

    #[test]
    fn decompresses_zstd_bytes() {
        let compressed = compress_bytes_zstd(b"hello-zstd").expect("compress zstd");

        let mut reader = decompress_bytes_to_reader(compressed).expect("zstd decompress");
        let mut out = String::new();
        reader.read_to_string(&mut out).expect("read output");

        assert_eq!(out, "hello-zstd");
    }
}
