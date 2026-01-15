use crate::scanner::ScanResults;
use anyhow::{Context, Result};
use std::path::Path;

pub fn write(results: &ScanResults, path: &Path) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("Failed to create CSV file: {}", path.display()))?;

    // Write header
    writer.write_record([
        "file_path",
        "line_number",
        "column",
        "matched_text",
        "pattern_name",
        "pattern",
        "severity",
        "category",
        "line_content",
        "context_before",
        "context_after",
    ])?;

    // Write matches
    for file_result in &results.file_results {
        for m in &file_result.matches {
            writer.write_record([
                &file_result.relative_path,
                &m.line_number.to_string(),
                &m.column.to_string(),
                &m.matched_text,
                m.pattern_name.as_deref().unwrap_or(""),
                &m.pattern_original,
                &m.severity.to_string(),
                m.category.as_deref().unwrap_or(""),
                &m.line_content,
                &m.context_before.join("\\n"),
                &m.context_after.join("\\n"),
            ])?;
        }
    }

    writer.flush()?;
    Ok(())
}
