use crate::cli::{Cli, Severity, default_extensions, default_ignore_patterns};
use crate::encoding::{is_binary, read_file_with_encoding, EncodingInfo, get_encoding_suggestion};
use crate::pattern::Pattern;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ignore::WalkBuilder;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A single match found in a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
    pub line_content: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
    pub pattern_name: Option<String>,
    pub pattern_original: String,
    pub severity: Severity,
    pub category: Option<String>,
}

/// Results for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    pub path: PathBuf,
    pub relative_path: String,
    pub matches: Vec<Match>,
    pub file_size: u64,
    pub encoding: String,
    pub encoding_suggestion: Option<String>,
    pub error: Option<String>,
}

/// Overall scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_time: DateTime<Utc>,
    pub duration_ms: u64,
    pub target_path: PathBuf,
    pub total_files_scanned: u64,
    pub total_files_with_matches: u64,
    pub total_matches: u64,
    pub total_bytes_scanned: u64,
    pub files_skipped_binary: u64,
    pub files_skipped_size: u64,
    pub files_with_errors: u64,
    pub patterns_used: usize,
    pub file_results: Vec<FileResult>,
    pub severity_summary: SeveritySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeveritySummary {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
}

impl SeveritySummary {
    pub fn add(&mut self, severity: &Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// The main scanner struct
pub struct Scanner {
    patterns: Vec<Pattern>,
    cli: Arc<Cli>,
    extensions: HashSet<String>,
    max_file_size: u64,
}

impl Scanner {
    pub fn new(cli: Cli, patterns: Vec<Pattern>) -> Result<Self> {
        let max_file_size = cli.parse_max_size()?;

        let extensions: HashSet<String> = if let Some(ref exts) = cli.extensions {
            exts.iter().map(|e| e.to_lowercase().trim_start_matches('.').to_string()).collect()
        } else {
            default_extensions().iter().map(|e| e.to_string()).collect()
        };

        Ok(Self {
            patterns,
            cli: Arc::new(cli),
            extensions,
            max_file_size,
        })
    }

    pub fn scan(&self) -> Result<ScanResults> {
        let start_time = std::time::Instant::now();
        let scan_time = Utc::now();

        // Collect files to scan
        let files = self.collect_files()?;

        if !self.cli.quiet {
            eprintln!(
                "🔍 Scanning {} files with {} patterns...",
                files.len(),
                self.patterns.len()
            );
        }

        // Setup counters
        let total_bytes_scanned = AtomicU64::new(0);
        let files_skipped_binary = AtomicU64::new(0);
        let files_skipped_size = AtomicU64::new(0);
        let files_with_errors = AtomicU64::new(0);

        // Setup progress bar
        let progress = if !self.cli.no_progress && !self.cli.quiet {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░"),
            );
            Some(pb)
        } else {
            None
        };

        // Configure thread pool
        let num_threads = self.cli.get_thread_count();
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()
            .ok();

        // Scan files in parallel
        let file_results: Vec<FileResult> = if let Some(ref pb) = progress {
            files
                .par_iter()
                .progress_with(pb.clone())
                .map(|path| {
                    self.scan_file(
                        path,
                        &total_bytes_scanned,
                        &files_skipped_binary,
                        &files_skipped_size,
                        &files_with_errors,
                    )
                })
                .collect()
        } else {
            files
                .par_iter()
                .map(|path| {
                    self.scan_file(
                        path,
                        &total_bytes_scanned,
                        &files_skipped_binary,
                        &files_skipped_size,
                        &files_with_errors,
                    )
                })
                .collect()
        };

        if let Some(pb) = progress {
            pb.finish_with_message("Done!");
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        // Calculate summaries
        let mut severity_summary = SeveritySummary::default();
        let mut total_matches = 0u64;
        let mut total_files_with_matches = 0u64;

        for result in &file_results {
            if !result.matches.is_empty() {
                total_files_with_matches += 1;
                for m in &result.matches {
                    total_matches += 1;
                    severity_summary.add(&m.severity);
                }
            }
        }

        // Filter by minimum severity if specified
        let file_results = if let Some(min_sev) = self.cli.min_severity {
            file_results
                .into_iter()
                .map(|mut fr| {
                    fr.matches.retain(|m| m.severity >= min_sev);
                    fr
                })
                .filter(|fr| !fr.matches.is_empty() || fr.error.is_some())
                .collect()
        } else {
            file_results.into_iter().filter(|fr| !fr.matches.is_empty() || fr.error.is_some()).collect()
        };

        Ok(ScanResults {
            scan_time,
            duration_ms,
            target_path: self.cli.target.clone(),
            total_files_scanned: files.len() as u64,
            total_files_with_matches,
            total_matches,
            total_bytes_scanned: total_bytes_scanned.load(Ordering::Relaxed),
            files_skipped_binary: files_skipped_binary.load(Ordering::Relaxed),
            files_skipped_size: files_skipped_size.load(Ordering::Relaxed),
            files_with_errors: files_with_errors.load(Ordering::Relaxed),
            patterns_used: self.patterns.len(),
            file_results,
            severity_summary,
        })
    }

    fn collect_files(&self) -> Result<Vec<PathBuf>> {
        let mut builder = WalkBuilder::new(&self.cli.target);

        builder
            .hidden(!self.cli.hidden)
            .follow_links(self.cli.follow_symlinks)
            .max_depth(if self.cli.is_recursive() { None } else { Some(1) })
            .standard_filters(true);

        // Add default ignore patterns
        for pattern in default_ignore_patterns() {
            builder.add_custom_ignore_filename(pattern);
        }

        // Add custom ignore patterns
        for pattern in &self.cli.ignore_patterns {
            if let Ok(glob) = globset::Glob::new(pattern) {
                let _ = builder.add_custom_ignore_filename(glob.glob());
            }
        }

        // Add ignore file if specified
        if let Some(ref ignore_file) = self.cli.ignore_file {
            if ignore_file.exists() {
                builder.add_ignore(ignore_file);
            }
        }

        let mut files = Vec::new();

        for entry in builder.build() {
            match entry {
                Ok(entry) => {
                    let path = entry.path();

                    // Skip directories
                    if path.is_dir() {
                        continue;
                    }

                    // Check extension
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if !self.extensions.contains(&ext_str) {
                            continue;
                        }
                    } else {
                        // No extension - skip unless it's in extensions list with empty
                        continue;
                    }

                    files.push(path.to_path_buf());
                }
                Err(e) => {
                    if self.cli.verbose {
                        eprintln!("Warning: Could not access path: {}", e);
                    }
                }
            }
        }

        Ok(files)
    }

    fn scan_file(
        &self,
        path: &Path,
        total_bytes: &AtomicU64,
        skipped_binary: &AtomicU64,
        skipped_size: &AtomicU64,
        error_count: &AtomicU64,
    ) -> FileResult {
        let relative_path = path
            .strip_prefix(&self.cli.target)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        // Get file metadata
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                error_count.fetch_add(1, Ordering::Relaxed);
                return FileResult {
                    path: path.to_path_buf(),
                    relative_path,
                    matches: vec![],
                    file_size: 0,
                    encoding: "unknown".to_string(),
                    encoding_suggestion: None,
                    error: Some(format!("Failed to read metadata: {}", e)),
                };
            }
        };

        let file_size = metadata.len();

        // Check file size
        if file_size > self.max_file_size {
            skipped_size.fetch_add(1, Ordering::Relaxed);
            return FileResult {
                path: path.to_path_buf(),
                relative_path,
                matches: vec![],
                file_size,
                encoding: "skipped".to_string(),
                encoding_suggestion: None,
                error: Some(format!("File too large: {} bytes", file_size)),
            };
        }

        // Read file content (try memory mapping for large files)
        let content_result = if file_size > 1024 * 1024 && !self.cli.no_binary_detection {
            // Use mmap for large files
            self.read_file_mmap(path)
        } else {
            read_file_with_encoding(path, self.cli.encoding.as_deref())
        };

        let (content, encoding_info) = match content_result {
            Ok((content, info)) => (content, info),
            Err(e) => {
                error_count.fetch_add(1, Ordering::Relaxed);
                return FileResult {
                    path: path.to_path_buf(),
                    relative_path,
                    matches: vec![],
                    file_size,
                    encoding: "error".to_string(),
                    encoding_suggestion: None,
                    error: Some(format!("Failed to read file: {}", e)),
                };
            }
        };

        // Check for binary content
        if !self.cli.no_binary_detection && is_binary(content.as_bytes()) {
            skipped_binary.fetch_add(1, Ordering::Relaxed);
            return FileResult {
                path: path.to_path_buf(),
                relative_path,
                matches: vec![],
                file_size,
                encoding: "binary".to_string(),
                encoding_suggestion: None,
                error: None,
            };
        }

        total_bytes.fetch_add(file_size, Ordering::Relaxed);

        // Scan content
        let lines: Vec<&str> = content.lines().collect();
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            for (line_idx, line) in lines.iter().enumerate() {
                for mat in pattern.regex.find_iter(line) {
                    let context_before = if self.cli.context > 0 {
                        lines[line_idx.saturating_sub(self.cli.context)..line_idx]
                            .iter()
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        vec![]
                    };

                    let context_after = if self.cli.context > 0 {
                        lines
                            .iter()
                            .skip(line_idx + 1)
                            .take(self.cli.context)
                            .map(|s| s.to_string())
                            .collect()
                    } else {
                        vec![]
                    };

                    matches.push(Match {
                        line_number: line_idx + 1,
                        column: mat.start() + 1,
                        matched_text: mat.as_str().to_string(),
                        line_content: line.to_string(),
                        context_before,
                        context_after,
                        pattern_name: pattern.name.clone(),
                        pattern_original: pattern.original.clone(),
                        severity: pattern.severity,
                        category: pattern.category.clone(),
                    });
                }
            }
        }

        let encoding_suggestion = if !encoding_info.is_utf8 {
            Some(get_encoding_suggestion(&encoding_info))
        } else {
            None
        };

        FileResult {
            path: path.to_path_buf(),
            relative_path,
            matches,
            file_size,
            encoding: encoding_info.encoding.name().to_string(),
            encoding_suggestion,
            error: None,
        }
    }

    fn read_file_mmap(&self, path: &Path) -> Result<(String, EncodingInfo)> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;

        let mmap = unsafe {
            Mmap::map(&file)
                .with_context(|| format!("Failed to mmap file: {}", path.display()))?
        };

        let encoding_info = crate::encoding::detect_encoding_from_bytes(&mmap)?;

        let (content, _, _) = encoding_info.encoding.decode(&mmap);

        Ok((content.into_owned(), encoding_info))
    }
}

/// Print scan summary to stderr
pub fn print_summary(results: &ScanResults, quiet: bool) {
    if quiet {
        return;
    }

    use colored::Colorize;

    eprintln!("\n{}", "═".repeat(60).bright_blue());
    eprintln!("{}", "  📊 SCAN SUMMARY".bright_white().bold());
    eprintln!("{}", "═".repeat(60).bright_blue());

    eprintln!(
        "  {} {} files scanned in {:.2}s",
        "📁".to_string(),
        results.total_files_scanned.to_string().bright_cyan(),
        results.duration_ms as f64 / 1000.0
    );

    eprintln!(
        "  {} {} bytes processed",
        "💾".to_string(),
        bytesize::ByteSize(results.total_bytes_scanned).to_string().bright_cyan()
    );

    if results.files_skipped_binary > 0 {
        eprintln!(
            "  {} {} binary files skipped",
            "⏭️ ".to_string(),
            results.files_skipped_binary.to_string().yellow()
        );
    }

    if results.files_with_errors > 0 {
        eprintln!(
            "  {} {} files with errors",
            "⚠️ ".to_string(),
            results.files_with_errors.to_string().red()
        );
    }

    eprintln!("{}", "─".repeat(60).bright_black());

    if results.total_matches > 0 {
        eprintln!(
            "  {} {} matches in {} files",
            "🎯".to_string(),
            results.total_matches.to_string().bright_yellow().bold(),
            results.total_files_with_matches.to_string().bright_yellow()
        );

        eprintln!("\n  {} Severity Breakdown:", "📈".to_string());

        if results.severity_summary.critical > 0 {
            eprintln!(
                "     {} Critical: {}",
                "🔴".to_string(),
                results.severity_summary.critical.to_string().bright_red().bold()
            );
        }
        if results.severity_summary.high > 0 {
            eprintln!(
                "     {} High:     {}",
                "🟠".to_string(),
                results.severity_summary.high.to_string().red()
            );
        }
        if results.severity_summary.medium > 0 {
            eprintln!(
                "     {} Medium:   {}",
                "🟡".to_string(),
                results.severity_summary.medium.to_string().yellow()
            );
        }
        if results.severity_summary.low > 0 {
            eprintln!(
                "     {} Low:      {}",
                "🟢".to_string(),
                results.severity_summary.low.to_string().green()
            );
        }
        if results.severity_summary.info > 0 {
            eprintln!(
                "     {} Info:     {}",
                "🔵".to_string(),
                results.severity_summary.info.to_string().blue()
            );
        }
    } else {
        eprintln!(
            "  {} {}",
            "✅".to_string(),
            "No matches found".bright_green().bold()
        );
    }

    eprintln!("{}", "═".repeat(60).bright_blue());
}
