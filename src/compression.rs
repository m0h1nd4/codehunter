use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Information about a compressed file
#[derive(Debug, Clone)]
pub struct CompressionInfo {
    pub is_compressed: bool,
    pub compression_type: CompressionType,
    pub original_filename: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionType {
    None,
    Gzip,
}

/// Check if a file is gzip compressed based on extension and magic bytes
pub fn detect_compression(path: &Path) -> Result<CompressionInfo> {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());

    // Check extension first
    if ext.as_deref() == Some("gz") || ext.as_deref() == Some("gzip") {
        // Verify magic bytes
        let file = File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;
        let mut reader = BufReader::new(file);
        let mut magic = [0u8; 2];

        if reader.read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b] {
            // Extract original filename from path (remove .gz)
            let original = path.file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string());

            return Ok(CompressionInfo {
                is_compressed: true,
                compression_type: CompressionType::Gzip,
                original_filename: original,
            });
        }
    }

    Ok(CompressionInfo {
        is_compressed: false,
        compression_type: CompressionType::None,
        original_filename: None,
    })
}

/// Reader that handles both compressed and uncompressed files with chunked reading
pub struct ChunkedReader {
    inner: Box<dyn BufRead + Send>,
    compression_type: CompressionType,
    bytes_read: u64,
}

impl ChunkedReader {
    /// Open a file for chunked reading, automatically detecting compression
    pub fn open(path: &Path) -> Result<Self> {
        let compression = detect_compression(path)?;
        let file = File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;

        let inner: Box<dyn BufRead + Send> = match compression.compression_type {
            CompressionType::Gzip => {
                let decoder = GzDecoder::new(file);
                Box::new(BufReader::with_capacity(64 * 1024, decoder))
            }
            CompressionType::None => {
                Box::new(BufReader::with_capacity(64 * 1024, file))
            }
        };

        Ok(Self {
            inner,
            compression_type: compression.compression_type,
            bytes_read: 0,
        })
    }

    /// Read the next chunk of lines
    /// Returns (lines, is_done)
    pub fn read_chunk(&mut self, max_lines: usize) -> Result<(Vec<String>, bool)> {
        let mut lines = Vec::with_capacity(max_lines);
        let mut is_done = false;

        for _ in 0..max_lines {
            let mut line = String::new();
            match self.inner.read_line(&mut line) {
                Ok(0) => {
                    is_done = true;
                    break;
                }
                Ok(n) => {
                    self.bytes_read += n as u64;
                    // Remove trailing newline
                    if line.ends_with('\n') {
                        line.pop();
                        if line.ends_with('\r') {
                            line.pop();
                        }
                    }
                    lines.push(line);
                }
                Err(e) => {
                    // Handle encoding errors gracefully - try to continue
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        // Skip invalid UTF-8 sequences
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        Ok((lines, is_done))
    }

    /// Read entire file into string (for smaller files)
    pub fn read_all(&mut self) -> Result<String> {
        let mut content = String::new();
        self.inner.read_to_string(&mut content)
            .context("Failed to read file content")?;
        self.bytes_read = content.len() as u64;
        Ok(content)
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub fn is_compressed(&self) -> bool {
        self.compression_type != CompressionType::None
    }
}

/// Read a gzip file and decompress it in memory
/// For files that fit in memory
pub fn read_gz_file(path: &Path) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open gzip file: {}", path.display()))?;

    let mut decoder = GzDecoder::new(file);
    let mut content = String::new();

    decoder.read_to_string(&mut content)
        .with_context(|| format!("Failed to decompress gzip file: {}", path.display()))?;

    Ok(content)
}

/// Streaming scan of a potentially large (or compressed) file
/// Processes file in chunks to minimize memory usage
///
/// The callback receives: (line_number, line_content) and returns matches
pub fn scan_file_chunked<F>(
    path: &Path,
    chunk_size: usize,
    context_lines: usize,
    scan_fn: F,
) -> Result<(Vec<ChunkedMatch>, u64)>
where
    F: FnMut(usize, &str) -> Vec<(usize, usize, String)>,
{
    scan_file_chunked_with_progress(path, chunk_size, context_lines, scan_fn, |_, _| {})
}

/// Streaming scan with progress callback
/// progress_fn receives: (bytes_read, lines_processed)
pub fn scan_file_chunked_with_progress<F, P>(
    path: &Path,
    chunk_size: usize,
    context_lines: usize,
    mut scan_fn: F,
    mut progress_fn: P,
) -> Result<(Vec<ChunkedMatch>, u64)>
where
    F: FnMut(usize, &str) -> Vec<(usize, usize, String)>, // Returns (column, pattern_idx, matched_text)
    P: FnMut(u64, usize), // Progress callback: (bytes_read, lines_processed)
{
    let mut reader = ChunkedReader::open(path)?;
    let mut all_matches = Vec::new();
    let mut line_number = 0usize;

    // Buffer for context
    let mut context_buffer: Vec<String> = Vec::with_capacity(context_lines);
    let mut pending_matches: Vec<(ChunkedMatch, usize)> = Vec::new(); // (match, remaining_after_lines)

    loop {
        let (lines, is_done) = reader.read_chunk(chunk_size)?;

        if lines.is_empty() && is_done {
            break;
        }

        for line in &lines {
            line_number += 1;

            // Update pending matches with context_after
            for (ref mut m, ref mut remaining) in &mut pending_matches {
                if *remaining > 0 {
                    m.context_after.push(line.clone());
                    *remaining -= 1;
                }
            }

            // Move completed matches to results
            pending_matches.retain(|(_, remaining)| *remaining > 0);

            // Scan this line
            let matches = scan_fn(line_number, line);

            for (column, pattern_idx, matched_text) in matches {
                let m = ChunkedMatch {
                    line_number,
                    column,
                    matched_text,
                    line_content: line.clone(),
                    context_before: context_buffer.clone(),
                    context_after: Vec::new(),
                    pattern_index: pattern_idx,
                };

                if context_lines > 0 {
                    pending_matches.push((m, context_lines));
                } else {
                    all_matches.push(m);
                }
            }

            // Update context buffer
            if context_lines > 0 {
                context_buffer.push(line.clone());
                if context_buffer.len() > context_lines {
                    context_buffer.remove(0);
                }
            }
        }

        // Report progress after each chunk
        progress_fn(reader.bytes_read(), line_number);

        if is_done {
            break;
        }
    }

    // Collect remaining pending matches
    for (m, _) in pending_matches {
        all_matches.push(m);
    }

    Ok((all_matches, reader.bytes_read()))
}

#[derive(Debug, Clone)]
pub struct ChunkedMatch {
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
    pub line_content: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
    pub pattern_index: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    #[test]
    fn test_detect_gzip() {
        // Create a temp gzip file
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"test content").unwrap();
        let compressed = encoder.finish().unwrap();

        let mut temp = NamedTempFile::new().unwrap();
        let path = temp.path().with_extension("gz");
        std::fs::write(&path, &compressed).unwrap();

        let info = detect_compression(&path).unwrap();
        assert!(info.is_compressed);
        assert_eq!(info.compression_type, CompressionType::Gzip);

        std::fs::remove_file(&path).ok();
    }
}
