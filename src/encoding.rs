use anyhow::{Context, Result};
use chardetng::EncodingDetector;
use encoding_rs::Encoding;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Result of encoding detection
#[derive(Debug, Clone)]
pub struct EncodingInfo {
    pub encoding: &'static Encoding,
    pub confidence: f32,
    pub is_utf8: bool,
}

/// Detect the encoding of a file
pub fn detect_encoding(path: &Path) -> Result<EncodingInfo> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file: {}", path.display()))?;

    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; 8192]; // Read first 8KB for detection
    let bytes_read = reader.read(&mut buffer)?;
    buffer.truncate(bytes_read);

    detect_encoding_from_bytes(&buffer)
}

/// Detect encoding from byte slice
pub fn detect_encoding_from_bytes(bytes: &[u8]) -> Result<EncodingInfo> {
    // First, check if it's valid UTF-8
    if std::str::from_utf8(bytes).is_ok() {
        return Ok(EncodingInfo {
            encoding: encoding_rs::UTF_8,
            confidence: 1.0,
            is_utf8: true,
        });
    }

    // Use chardetng for detection
    let mut detector = EncodingDetector::new();
    detector.feed(bytes, true);
    let encoding = detector.guess(None, true);

    // Calculate a rough confidence score
    let confidence = if encoding == encoding_rs::UTF_8 {
        0.5 // UTF-8 guess but invalid bytes
    } else {
        0.8 // Non-UTF-8 encoding detected
    };

    Ok(EncodingInfo {
        encoding,
        confidence,
        is_utf8: false,
    })
}

/// Read file content with automatic encoding detection
pub fn read_file_with_encoding(
    path: &Path,
    force_encoding: Option<&str>,
) -> Result<(String, EncodingInfo)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let encoding_info = if let Some(enc_name) = force_encoding {
        let encoding = Encoding::for_label(enc_name.as_bytes())
            .with_context(|| format!("Unknown encoding: {}", enc_name))?;
        EncodingInfo {
            encoding,
            confidence: 1.0,
            is_utf8: encoding == encoding_rs::UTF_8,
        }
    } else {
        detect_encoding_from_bytes(&bytes)?
    };

    let (content, _, had_errors) = encoding_info.encoding.decode(&bytes);

    if had_errors {
        log::warn!(
            "Encoding errors in file {} (using {})",
            path.display(),
            encoding_info.encoding.name()
        );
    }

    Ok((content.into_owned(), encoding_info))
}

/// Check if bytes appear to be binary content
pub fn is_binary(bytes: &[u8]) -> bool {
    // Check for null bytes (common in binary files)
    if bytes.contains(&0) {
        return true;
    }

    // Check for high ratio of non-printable characters
    let sample_size = bytes.len().min(8192);
    let sample = &bytes[..sample_size];

    let non_text_count = sample
        .iter()
        .filter(|&&b| {
            // Control characters except common whitespace
            (b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
                // DEL and high control chars
                || b == 0x7F
        })
        .count();

    // If more than 10% are control characters, likely binary
    (non_text_count as f64 / sample_size as f64) > 0.1
}

/// Get human-readable encoding suggestions
pub fn get_encoding_suggestion(encoding_info: &EncodingInfo) -> String {
    if encoding_info.is_utf8 {
        "File is UTF-8 encoded.".to_string()
    } else {
        format!(
            "File appears to be {} encoded (confidence: {:.0}%). \
             Consider using --encoding {} to force this encoding.",
            encoding_info.encoding.name(),
            encoding_info.confidence * 100.0,
            encoding_info.encoding.name().to_lowercase()
        )
    }
}

/// List of common encodings for help text
pub fn common_encodings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("utf-8", "Unicode (default)"),
        ("utf-16le", "Unicode UTF-16 Little Endian"),
        ("utf-16be", "Unicode UTF-16 Big Endian"),
        ("iso-8859-1", "Latin-1 (Western European)"),
        ("iso-8859-15", "Latin-9 (Western European with Euro)"),
        ("windows-1252", "Windows Western European"),
        ("windows-1251", "Windows Cyrillic"),
        ("iso-8859-2", "Latin-2 (Central European)"),
        ("shift_jis", "Japanese Shift-JIS"),
        ("euc-jp", "Japanese EUC-JP"),
        ("gb18030", "Chinese GB18030"),
        ("big5", "Chinese Big5 (Traditional)"),
        ("euc-kr", "Korean EUC-KR"),
        ("koi8-r", "Russian KOI8-R"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_detection() {
        let content = "Hello, World! 🎉";
        let info = detect_encoding_from_bytes(content.as_bytes()).unwrap();
        assert!(info.is_utf8);
    }

    #[test]
    fn test_binary_detection() {
        let binary = vec![0x00, 0x01, 0x02, 0xFF, 0xFE];
        assert!(is_binary(&binary));

        let text = b"Hello, World!";
        assert!(!is_binary(text));
    }
}
