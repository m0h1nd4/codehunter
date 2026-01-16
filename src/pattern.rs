use crate::cli::Severity;
use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Pattern {
    pub original: String,
    pub regex: Regex,
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Severity,
    pub category: Option<String>,
}

impl Pattern {
    pub fn new(pattern: &str, literal: bool, ignore_case: bool) -> Result<Self> {
        let regex_str = if literal {
            regex::escape(pattern)
        } else {
            pattern.to_string()
        };

        let regex_str = if ignore_case {
            format!("(?i){}", regex_str)
        } else {
            regex_str
        };

        let regex = Regex::new(&regex_str)
            .with_context(|| format!("Invalid regex pattern: {}", pattern))?;

        Ok(Self {
            original: pattern.to_string(),
            regex,
            name: None,
            description: None,
            severity: Severity::Medium,
            category: None,
        })
    }

    pub fn with_metadata(
        mut self,
        name: Option<String>,
        description: Option<String>,
        severity: Severity,
        category: Option<String>,
    ) -> Self {
        self.name = name;
        self.description = description;
        self.severity = severity;
        self.category = category;
        self
    }
}

/// Parse a pattern file with the following format:
/// ```
/// # Comment line
/// pattern1                           # Inline comment
/// pattern2 | name | description | severity | category
/// eval\s*\(\s*base64_decode | Base64 Eval | PHP backdoor pattern | critical | backdoor
/// ```
pub fn parse_pattern_file(path: &Path, literal: bool, ignore_case: bool) -> Result<Vec<Pattern>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read pattern file: {}", path.display()))?;

    parse_patterns_from_string(&content, literal, ignore_case)
}

pub fn parse_patterns_from_string(content: &str, literal: bool, ignore_case: bool) -> Result<Vec<Pattern>> {
    let mut patterns = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and pure comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Remove inline comments (but be careful with regex containing #)
        let line = remove_inline_comment(line);

        if line.is_empty() {
            continue;
        }

        // Check if line has metadata (pipe-separated)
        // Parse from right to left: last 4 fields are metadata, everything before is the pattern
        // This allows patterns to contain | characters (e.g., regex alternation)
        let parts: Vec<&str> = line.split('|').collect();

        let pattern = if parts.len() >= 5 {
            // Has full metadata (pattern | name | description | severity | category)
            // Join all parts except the last 4 as the pattern
            let pattern_str = parts[..parts.len() - 4]
                .iter()
                .map(|s| s.trim())
                .collect::<Vec<_>>()
                .join("|");
            let name = parts.get(parts.len() - 4).map(|s| s.trim()).and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });
            let description = parts.get(parts.len() - 3).map(|s| s.trim()).and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });
            let severity = parts.get(parts.len() - 2)
                .map(|s| s.trim())
                .and_then(|s| parse_severity(s))
                .unwrap_or(Severity::Medium);
            let category = parts.get(parts.len() - 1).map(|s| s.trim()).and_then(|s| if s.is_empty() { None } else { Some(s.to_string()) });

            Pattern::new(&pattern_str, literal, ignore_case)
                .with_context(|| format!("Invalid pattern at line {}: {}", line_num + 1, pattern_str))?
                .with_metadata(name, description, severity, category)
        } else {
            // No metadata or incomplete metadata - treat entire line as pattern
            Pattern::new(&line, literal, ignore_case)
                .with_context(|| format!("Invalid pattern at line {}: {}", line_num + 1, line))?
        };

        patterns.push(pattern);
    }

    Ok(patterns)
}

fn remove_inline_comment(line: &str) -> &str {
    // Find # that's not escaped and not inside brackets
    let mut in_bracket = 0;
    let mut escaped = false;

    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match c {
            '\\' => escaped = true,
            '[' => in_bracket += 1,
            ']' if in_bracket > 0 => in_bracket -= 1,
            '#' if in_bracket == 0 => {
                // Check if there's whitespace before the #
                let before = &line[..i];
                if before.ends_with(' ') || before.ends_with('\t') {
                    return before.trim_end();
                }
            }
            _ => {}
        }
    }

    line
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().trim() {
        "info" | "i" | "0" => Some(Severity::Info),
        "low" | "l" | "1" => Some(Severity::Low),
        "medium" | "med" | "m" | "2" => Some(Severity::Medium),
        "high" | "h" | "3" => Some(Severity::High),
        "critical" | "crit" | "c" | "4" => Some(Severity::Critical),
        _ => None,
    }
}

/// Common malware signature patterns (built-in)
pub fn builtin_patterns(ignore_case: bool) -> Vec<Pattern> {
    let patterns_data: Vec<(&str, &str, &str, Severity, &str)> = vec![
        // PHP Backdoors
        (r#"eval\s*\(\s*base64_decode\s*\("#, "Base64 Eval", "Encoded PHP execution - common backdoor", Severity::Critical, "backdoor"),
        (r#"eval\s*\(\s*gzinflate\s*\("#, "Gzinflate Eval", "Compressed PHP execution", Severity::Critical, "backdoor"),
        (r#"eval\s*\(\s*gzuncompress\s*\("#, "Gzuncompress Eval", "Compressed PHP execution", Severity::Critical, "backdoor"),
        (r#"eval\s*\(\s*str_rot13\s*\("#, "ROT13 Eval", "Obfuscated PHP execution", Severity::High, "backdoor"),
        (r#"assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#, "Assert Injection", "PHP code injection via assert", Severity::Critical, "backdoor"),
        (r#"preg_replace\s*\([^)]*['"][^'"]*e['""]"#, "Preg Replace Eval", "Code execution via preg_replace /e modifier", Severity::Critical, "backdoor"),
        (r#"create_function\s*\([^)]*\$_(GET|POST|REQUEST)"#, "Create Function Injection", "Dynamic function creation with user input", Severity::Critical, "backdoor"),
        
        // Shell Commands
        (r#"(shell_exec|system|passthru|exec|popen)\s*\(\s*\$"#, "Shell Execution", "Shell command with variable input", Severity::High, "shell"),
        (r#"(shell_exec|system|passthru|exec|popen)\s*\(\s*['""]"#, "Shell Command", "Direct shell command execution", Severity::Medium, "shell"),
        (r#"`\s*\$_(GET|POST|REQUEST|COOKIE)"#, "Backtick Injection", "Shell execution via backticks", Severity::Critical, "shell"),
        
        // File Operations
        (r#"(file_put_contents|fwrite|fputs)\s*\([^)]*\$_(GET|POST|REQUEST)"#, "File Write Injection", "Writing user input to files", Severity::Critical, "file"),
        (r#"(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)"#, "File Include Injection", "Local/Remote file inclusion", Severity::Critical, "lfi"),
        (r#"(move_uploaded_file)\s*\("#, "File Upload", "File upload handler - check for validation", Severity::Medium, "upload"),
        
        // Webshells
        (r#"FilesMan|WSO|c99|r57|b374k"#, "Known Webshell", "Known webshell signature", Severity::Critical, "webshell"),
        (r#"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['"][a-z0-9]{1,3}['"]\s*\]"#, "Short Parameter", "Suspiciously short parameter names", Severity::Low, "suspicious"),
        
        // Obfuscation
        (r#"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}"#, "Hex Encoded", "Long hex-encoded string", Severity::High, "obfuscation"),
        (r#"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)"#, "Chr Concatenation", "Character code obfuscation", Severity::Medium, "obfuscation"),
        (r#"base64_decode\s*\(\s*['"][A-Za-z0-9+/=]{100,}['""]"#, "Long Base64", "Long base64 encoded string", Severity::High, "obfuscation"),
        
        // JavaScript Malware
        (r#"document\.write\s*\(\s*unescape\s*\("#, "Document Write Unescape", "Obfuscated JavaScript injection", Severity::High, "javascript"),
        (r#"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)"#, "JavaScript Packer", "Packed/obfuscated JavaScript", Severity::Medium, "javascript"),
        (r#"String\.fromCharCode\s*\([^)]{50,}\)"#, "FromCharCode Obfuscation", "Character code obfuscation in JS", Severity::Medium, "javascript"),
        
        // SQL Injection Patterns (in code)
        (r#"\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\."#, "SQL Concatenation", "Direct user input in SQL query", Severity::High, "sqli"),
        
        // Crypto Miners
        (r#"coinhive|cryptonight|minero|coin-hive"#, "Crypto Miner", "Cryptocurrency mining script", Severity::High, "miner"),
        
        // Malicious Redirects
        (r#"header\s*\(\s*['"]Location:\s*https?://[^'""]+"#, "Redirect", "HTTP redirect - verify destination", Severity::Low, "redirect"),
        (r#"window\.location\s*=\s*['"]https?://"#, "JS Redirect", "JavaScript redirect", Severity::Low, "redirect"),
        
        // Suspicious Functions
        (r#"(unserialize|maybe_unserialize)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"#, "Unserialize Injection", "Unsafe deserialization", Severity::Critical, "deserialization"),
        (r#"call_user_func(_array)?\s*\(\s*\$"#, "Dynamic Call", "Dynamic function call with variable", Severity::High, "dynamic"),
    ];

    patterns_data
        .into_iter()
        .filter_map(|(pattern, name, desc, severity, category)| {
            Pattern::new(pattern, false, ignore_case)
                .ok()
                .map(|p| p.with_metadata(
                    Some(name.to_string()),
                    Some(desc.to_string()),
                    severity,
                    Some(category.to_string()),
                ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_pattern() {
        let pattern = Pattern::new(r"eval\(", false, false).unwrap();
        assert!(pattern.regex.is_match("eval("));
    }

    #[test]
    fn test_parse_literal_pattern() {
        let pattern = Pattern::new(r"test.+", true, false).unwrap();
        assert!(pattern.regex.is_match("test.+"));
        assert!(!pattern.regex.is_match("testing"));
    }

    #[test]
    fn test_parse_case_insensitive() {
        let pattern = Pattern::new("EVAL", false, true).unwrap();
        assert!(pattern.regex.is_match("eval"));
        assert!(pattern.regex.is_match("EVAL"));
    }

    #[test]
    fn test_parse_pattern_file_content() {
        let content = r#"
# This is a comment
eval\(base64_decode | Base64 Eval | Critical backdoor | critical | backdoor
shell_exec\( | Shell Exec | Shell execution | high

# Another comment
simple_pattern
"#;
        let patterns = parse_patterns_from_string(content, false, false).unwrap();
        assert_eq!(patterns.len(), 3);
        assert_eq!(patterns[0].severity, Severity::Critical);
        assert_eq!(patterns[1].severity, Severity::High);
        assert_eq!(patterns[2].severity, Severity::Medium);
    }
}
