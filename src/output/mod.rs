pub mod json;
pub mod csv;
pub mod text;
pub mod html;

use crate::cli::OutputFormat;
use crate::scanner::ScanResults;
use anyhow::Result;
use std::path::Path;

pub fn write_output(results: &ScanResults, path: &Path, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => json::write(results, path),
        OutputFormat::Csv => csv::write(results, path),
        OutputFormat::Text => text::write(results, path),
        OutputFormat::Html => html::write(results, path),
    }
}
