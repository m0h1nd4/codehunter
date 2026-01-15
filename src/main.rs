mod cli;
mod encoding;
mod output;
mod pattern;
mod scanner;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::Cli;
use colored::Colorize;
use pattern::{builtin_patterns, parse_pattern_file, Pattern};
use scanner::{print_summary, Scanner};

fn main() {
    env_logger::init();

    if let Err(e) = run() {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Validate inputs
    if !cli.target.exists() {
        bail!("Target path does not exist: {}", cli.target.display());
    }

    // Print banner
    if !cli.quiet {
        print_banner();
    }

    // Load patterns
    let patterns = load_patterns(&cli)?;

    if patterns.is_empty() {
        bail!("No patterns to search for. Provide -p/--pattern or -f/--pattern-file");
    }

    if !cli.quiet {
        eprintln!(
            "📋 Loaded {} pattern{}",
            patterns.len().to_string().bright_cyan(),
            if patterns.len() == 1 { "" } else { "s" }
        );
    }

    // Create scanner
    let scanner = Scanner::new(cli.clone(), patterns)?;

    // Run scan
    let results = scanner.scan()?;

    // Print summary
    print_summary(&results, cli.quiet);

    // Write output
    output::write_output(&results, &cli.output, cli.format)
        .with_context(|| format!("Failed to write output to: {}", cli.output.display()))?;

    if !cli.quiet {
        eprintln!(
            "\n📄 Report saved to: {}",
            cli.output.display().to_string().bright_green()
        );
    }

    // Exit with code 1 if matches found (useful for CI/CD)
    if results.total_matches > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn load_patterns(cli: &Cli) -> Result<Vec<Pattern>> {
    let mut patterns = Vec::new();

    // Load from pattern file
    if let Some(ref pattern_file) = cli.pattern_file {
        if !pattern_file.exists() {
            bail!("Pattern file does not exist: {}", pattern_file.display());
        }

        let file_patterns = parse_pattern_file(pattern_file, cli.literal, cli.ignore_case)?;
        
        if !cli.quiet && cli.verbose {
            eprintln!(
                "  Loaded {} patterns from {}",
                file_patterns.len(),
                pattern_file.display()
            );
        }
        
        patterns.extend(file_patterns);
    }

    // Load single pattern from CLI
    if let Some(ref pattern_str) = cli.pattern {
        let pattern = Pattern::new(pattern_str, cli.literal, cli.ignore_case)?;
        patterns.push(pattern);
    }

    // If no patterns provided and builtin flag used (we could add --builtin flag)
    // For now, if no patterns at all, suggest using builtin
    if patterns.is_empty() {
        if !cli.quiet {
            eprintln!(
                "{}",
                "💡 Tip: No patterns provided. Using built-in malware signatures.".yellow()
            );
        }
        patterns = builtin_patterns(cli.ignore_case);
    }

    Ok(patterns)
}

fn print_banner() {
    let banner = r#"
   ____          _      _   _             _            
  / ___|___   __| | ___| | | |_   _ _ __ | |_ ___ _ __ 
 | |   / _ \ / _` |/ _ \ |_| | | | | '_ \| __/ _ \ '__|
 | |__| (_) | (_| |  __/  _  | |_| | | | | ||  __/ |   
  \____\___/ \__,_|\___|_| |_|\__,_|_| |_|\__\___|_|   
                                                       
"#;

    eprintln!("{}", banner.bright_cyan());
    eprintln!(
        "  {} v1.0.0 - High-Performance Malware Signature Scanner",
        "CodeHunter".bright_white().bold()
    );
    eprintln!(
        "  {}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".bright_black()
    );
    eprintln!();
}
