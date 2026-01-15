use crate::cli::Severity;
use crate::scanner::ScanResults;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub fn write(results: &ScanResults, path: &Path) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("Failed to create output file: {}", path.display()))?;

    let mut writer = BufWriter::new(file);

    // Header
    writeln!(writer, "╔══════════════════════════════════════════════════════════════════════════════╗")?;
    writeln!(writer, "║                           CODEHUNTER SCAN REPORT                             ║")?;
    writeln!(writer, "╚══════════════════════════════════════════════════════════════════════════════╝")?;
    writeln!(writer)?;

    // Summary
    writeln!(writer, "SCAN SUMMARY")?;
    writeln!(writer, "────────────────────────────────────────────────────────────────────────────────")?;
    writeln!(writer, "  Scan Time:        {}", results.scan_time.format("%Y-%m-%d %H:%M:%S UTC"))?;
    writeln!(writer, "  Duration:         {:.2}s", results.duration_ms as f64 / 1000.0)?;
    writeln!(writer, "  Target:           {}", results.target_path.display())?;
    writeln!(writer, "  Files Scanned:    {}", results.total_files_scanned)?;
    writeln!(writer, "  Bytes Processed:  {} bytes", results.total_bytes_scanned)?;
    writeln!(writer, "  Patterns Used:    {}", results.patterns_used)?;
    writeln!(writer)?;
    writeln!(writer, "  Total Matches:    {}", results.total_matches)?;
    writeln!(writer, "  Files w/ Matches: {}", results.total_files_with_matches)?;
    writeln!(writer)?;

    // Severity breakdown
    writeln!(writer, "SEVERITY BREAKDOWN")?;
    writeln!(writer, "────────────────────────────────────────────────────────────────────────────────")?;
    writeln!(writer, "  [CRITICAL] {}", results.severity_summary.critical)?;
    writeln!(writer, "  [HIGH]     {}", results.severity_summary.high)?;
    writeln!(writer, "  [MEDIUM]   {}", results.severity_summary.medium)?;
    writeln!(writer, "  [LOW]      {}", results.severity_summary.low)?;
    writeln!(writer, "  [INFO]     {}", results.severity_summary.info)?;
    writeln!(writer)?;

    // Detailed findings
    if !results.file_results.is_empty() {
        writeln!(writer, "╔══════════════════════════════════════════════════════════════════════════════╗")?;
        writeln!(writer, "║                              DETAILED FINDINGS                               ║")?;
        writeln!(writer, "╚══════════════════════════════════════════════════════════════════════════════╝")?;
        writeln!(writer)?;

        for file_result in &results.file_results {
            if file_result.matches.is_empty() {
                continue;
            }

            writeln!(writer, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
            writeln!(writer, "FILE: {}", file_result.relative_path)?;
            writeln!(writer, "Size: {} bytes | Encoding: {}", file_result.file_size, file_result.encoding)?;
            writeln!(writer, "Matches: {}", file_result.matches.len())?;
            writeln!(writer, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
            writeln!(writer)?;

            for (idx, m) in file_result.matches.iter().enumerate() {
                let severity_indicator = match m.severity {
                    Severity::Critical => "[!!!CRITICAL!!!]",
                    Severity::High => "[!! HIGH !!]",
                    Severity::Medium => "[! MEDIUM !]",
                    Severity::Low => "[ LOW ]",
                    Severity::Info => "[ INFO ]",
                };

                writeln!(writer, "  Match #{} {}", idx + 1, severity_indicator)?;
                writeln!(writer, "  ──────────────────────────────────────────────────────────────────────────")?;
                writeln!(writer, "  Location:    Line {}, Column {}", m.line_number, m.column)?;
                
                if let Some(ref name) = m.pattern_name {
                    writeln!(writer, "  Pattern:     {} ({})", name, m.pattern_original)?;
                } else {
                    writeln!(writer, "  Pattern:     {}", m.pattern_original)?;
                }
                
                if let Some(ref cat) = m.category {
                    writeln!(writer, "  Category:    {}", cat)?;
                }

                writeln!(writer, "  Matched:     \"{}\"", m.matched_text)?;
                writeln!(writer)?;

                // Context before
                if !m.context_before.is_empty() {
                    for (i, line) in m.context_before.iter().enumerate() {
                        let line_num = m.line_number - m.context_before.len() + i;
                        writeln!(writer, "  {:>6} │ {}", line_num, line)?;
                    }
                }

                // Matched line (highlighted)
                writeln!(writer, "  {:>6} │ >>> {} <<<", m.line_number, m.line_content)?;

                // Context after
                if !m.context_after.is_empty() {
                    for (i, line) in m.context_after.iter().enumerate() {
                        let line_num = m.line_number + 1 + i;
                        writeln!(writer, "  {:>6} │ {}", line_num, line)?;
                    }
                }

                writeln!(writer)?;
            }
        }
    }

    // Files with errors
    let error_files: Vec<_> = results
        .file_results
        .iter()
        .filter(|f| f.error.is_some())
        .collect();

    if !error_files.is_empty() {
        writeln!(writer)?;
        writeln!(writer, "FILES WITH ERRORS")?;
        writeln!(writer, "────────────────────────────────────────────────────────────────────────────────")?;
        for f in error_files {
            writeln!(
                writer,
                "  {} - {}",
                f.relative_path,
                f.error.as_deref().unwrap_or("Unknown error")
            )?;
        }
    }

    writeln!(writer)?;
    writeln!(writer, "════════════════════════════════════════════════════════════════════════════════")?;
    writeln!(writer, "                              END OF REPORT                                     ")?;
    writeln!(writer, "════════════════════════════════════════════════════════════════════════════════")?;

    writer.flush()?;
    Ok(())
}
