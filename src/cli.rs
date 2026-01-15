use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "codehunter",
    author = "Security Team",
    version = "1.0.0",
    about = "🔍 High-performance malware signature scanner for code files",
    long_about = "CodeHunter is a blazingly fast CLI tool for scanning code files for malware signatures, \
                  backdoors, and suspicious patterns. Designed for security professionals to analyze \
                  compromised websites and codebases.",
    after_help = "EXAMPLES:\n    \
        codehunter -t /var/www/html -p 'eval\\(base64_decode'\n    \
        codehunter -t ./src -f signatures.txt -o report.json\n    \
        codehunter -t /website --format html -o report.html --context 3\n    \
        codehunter -t . -p 'shell_exec' --no-recursive --format csv"
)]
pub struct Cli {
    /// Target file or directory to scan
    #[arg(short, long, required = true)]
    pub target: PathBuf,

    /// Single pattern (string or regex) to search for
    #[arg(short, long, conflicts_with = "pattern_file")]
    pub pattern: Option<String>,

    /// File containing patterns (one per line, supports comments with #)
    #[arg(short = 'f', long, conflicts_with = "pattern")]
    pub pattern_file: Option<PathBuf>,

    /// Output file path
    #[arg(short, long, default_value = "codehunter_report.json")]
    pub output: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    pub format: OutputFormat,

    /// Number of context lines to show before and after matches
    #[arg(short, long, default_value = "0")]
    pub context: usize,

    /// Scan subdirectories recursively
    #[arg(short = 'r', long, default_value = "true")]
    pub recursive: bool,

    /// Disable recursive scanning
    #[arg(long = "no-recursive")]
    pub no_recursive: bool,

    /// Path to ignore file (gitignore-style syntax)
    #[arg(short, long)]
    pub ignore_file: Option<PathBuf>,

    /// Additional patterns to ignore (can be used multiple times)
    #[arg(long = "ignore", action = clap::ArgAction::Append)]
    pub ignore_patterns: Vec<String>,

    /// File extensions to scan (comma-separated, e.g., "php,js,html")
    #[arg(short = 'e', long, value_delimiter = ',')]
    pub extensions: Option<Vec<String>>,

    /// Maximum file size to scan (e.g., "10MB", "1GB")
    #[arg(long, default_value = "50MB")]
    pub max_size: String,

    /// Number of threads to use (0 = auto-detect)
    #[arg(long, default_value = "0")]
    pub threads: usize,

    /// Treat patterns as literal strings instead of regex
    #[arg(long)]
    pub literal: bool,

    /// Case-insensitive matching
    #[arg(short = 'i', long)]
    pub ignore_case: bool,

    /// Disable progress bar
    #[arg(long)]
    pub no_progress: bool,

    /// Quiet mode - only output errors
    #[arg(short, long)]
    pub quiet: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Force specific encoding (e.g., "utf-8", "iso-8859-1", "windows-1252")
    #[arg(long)]
    pub encoding: Option<String>,

    /// Follow symbolic links
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Include hidden files and directories
    #[arg(long)]
    pub hidden: bool,

    /// Skip binary file detection (scan all files)
    #[arg(long)]
    pub no_binary_detection: bool,

    /// Minimum severity level to report (if patterns have severity)
    #[arg(long, value_enum)]
    pub min_severity: Option<Severity>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Csv,
    Text,
    Html,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

impl Cli {
    pub fn is_recursive(&self) -> bool {
        self.recursive && !self.no_recursive
    }

    pub fn get_thread_count(&self) -> usize {
        if self.threads == 0 {
            num_cpus::get()
        } else {
            self.threads
        }
    }

    pub fn parse_max_size(&self) -> anyhow::Result<u64> {
        parse_size(&self.max_size)
    }
}

fn parse_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim().to_uppercase();
    let (num_str, multiplier) = if s.ends_with("GB") {
        (&s[..s.len() - 2], 1024 * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024)
    } else if s.ends_with('B') {
        (&s[..s.len() - 1], 1)
    } else {
        (s.as_str(), 1)
    };

    let num: u64 = num_str.trim().parse()?;
    Ok(num * multiplier)
}

/// Default file extensions to scan
pub fn default_extensions() -> Vec<&'static str> {
    vec![
        // Web
        "php", "phtml", "php3", "php4", "php5", "php7", "phps", "inc",
        "html", "htm", "xhtml", "shtml",
        "js", "mjs", "cjs", "jsx", "ts", "tsx",
        "css", "scss", "sass", "less",
        "asp", "aspx", "ashx", "asmx", "ascx",
        "jsp", "jspx",
        // Scripts
        "py", "pyw", "pyx",
        "rb", "erb", "rake",
        "pl", "pm", "cgi",
        "sh", "bash", "zsh", "fish",
        "ps1", "psm1", "psd1",
        "bat", "cmd",
        "lua",
        // Compiled Languages
        "c", "h", "cpp", "hpp", "cc", "cxx", "hxx",
        "cs",
        "java",
        "go",
        "rs",
        "swift",
        "kt", "kts",
        "scala",
        // Config / Data
        "json", "xml", "yaml", "yml", "toml", "ini", "conf", "cfg",
        "sql",
        "htaccess", "htpasswd",
        // Docs
        "txt", "md", "markdown", "rst",
        "csv", "tsv",
        // Other
        "vue", "svelte",
        "twig", "blade.php", "mustache", "hbs",
        "env", "env.local", "env.production",
    ]
}

/// Default directories to ignore
pub fn default_ignore_patterns() -> Vec<&'static str> {
    vec![
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        ".bzr",
        "vendor",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".nox",
        "venv",
        ".venv",
        "env",
        ".env",
        "virtualenv",
        ".idea",
        ".vscode",
        ".vs",
        "*.min.js",
        "*.min.css",
        "*.map",
        "*.lock",
        "package-lock.json",
        "yarn.lock",
        "composer.lock",
        "Cargo.lock",
        ".DS_Store",
        "Thumbs.db",
        "*.log",
        "*.bak",
        "*.swp",
        "*.swo",
        "*~",
        "dist",
        "build",
        "target",
        "out",
        "bin",
        "obj",
        ".cache",
        ".npm",
        ".yarn",
    ]
}
