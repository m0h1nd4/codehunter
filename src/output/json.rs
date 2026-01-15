use crate::scanner::ScanResults;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

pub fn write(results: &ScanResults, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create output file: {}", path.display()))?;

    let writer = BufWriter::new(file);

    serde_json::to_writer_pretty(writer, results)
        .with_context(|| format!("Failed to write JSON to: {}", path.display()))?;

    Ok(())
}
