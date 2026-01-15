# 🔍 CodeHunter

**High-Performance Malware Signature Scanner for Code Files**

CodeHunter ist ein blitzschnelles CLI-Tool zur Analyse von Code-Dateien auf Malware-Signaturen, Backdoors und verdächtige Muster. Entwickelt für Security-Professionals zur Analyse kompromittierter Webseiten und Code-Repositories.

## ✨ Features

- 🚀 **Extrem schnell** - Parallelisierte Analyse mit Rayon, Memory-Mapping für große Dateien
- 📝 **Flexible Pattern** - Regex oder Literal-Strings, einzeln oder aus Datei
- 📊 **Mehrere Ausgabeformate** - JSON, CSV, Plain Text, interaktiver HTML-Report
- 🎯 **Severity-Levels** - Critical, High, Medium, Low, Info
- 📁 **Smart File-Handling** - Automatische Encoding-Erkennung, Binary-Detection
- 🔒 **Built-in Signatures** - Vorkonfigurierte Malware-Patterns
- ⚙️ **Gitignore-Style** - Flexible Ignore-Patterns
- 📈 **Fortschrittsanzeige** - Live-Progress-Bar während des Scans

## 🚀 Installation

```bash
# Aus Source kompilieren
cargo build --release

# Binary findet sich in:
./target/release/codehunter
```

## 📖 Verwendung

### Grundlegende Beispiele

```bash
# Mit einzelnem Pattern scannen
codehunter -t /var/www/html -p 'eval\(base64_decode'

# Mit Pattern-Datei scannen
codehunter -t ./website -f signatures.txt -o report.json

# HTML-Report mit Kontext erstellen
codehunter -t /path/to/code --format html -o report.html --context 3

# Built-in Malware-Signaturen verwenden (Standard wenn keine Pattern angegeben)
codehunter -t /suspicious/code -o scan_results.json

# CSV-Export für Excel/Analyse
codehunter -t . --format csv -o findings.csv
```

### Alle Optionen

```
USAGE:
    codehunter [OPTIONS] --target <TARGET>

OPTIONS:
    -t, --target <TARGET>           Target file or directory to scan
    -p, --pattern <PATTERN>         Single pattern (string or regex) to search for
    -f, --pattern-file <FILE>       File containing patterns (one per line)
    -o, --output <OUTPUT>           Output file path [default: codehunter_report.json]
        --format <FORMAT>           Output format [json, csv, text, html]
    -c, --context <N>               Context lines before/after matches [default: 0]
    -r, --recursive                 Scan subdirectories [default: true]
        --no-recursive              Disable recursive scanning
    -i, --ignore-file <FILE>        Path to gitignore-style ignore file
        --ignore <PATTERN>          Additional patterns to ignore (repeatable)
    -e, --extensions <EXT,EXT>      File extensions to scan (comma-separated)
        --max-size <SIZE>           Maximum file size [default: 50MB]
        --threads <N>               Number of threads (0 = auto) [default: 0]
        --literal                   Treat patterns as literal strings
    -i, --ignore-case               Case-insensitive matching
        --no-progress               Disable progress bar
    -q, --quiet                     Quiet mode
    -v, --verbose                   Verbose output
        --encoding <ENCODING>       Force specific encoding
        --follow-symlinks           Follow symbolic links
        --hidden                    Include hidden files
        --no-binary-detection       Skip binary file detection
        --min-severity <LEVEL>      Minimum severity to report
```

## 📋 Pattern-Datei Format

Pattern-Dateien unterstützen Kommentare und optionale Metadaten:

```
# Einfache Pattern (eine pro Zeile)
eval\(base64_decode
shell_exec\s*\(

# Mit Metadaten: Pattern | Name | Beschreibung | Severity | Kategorie
eval\s*\(\s*base64_decode | Base64 Eval | PHP Backdoor Pattern | critical | backdoor
preg_replace\s*\([^)]*e['\"] | Preg Replace Eval | Code execution | high | injection
\$_(GET|POST)\s*\[ | User Input | Direct user input usage | medium | suspicious

# Severity-Levels: info, low, medium, high, critical
# Kategorien: backdoor, shell, injection, webshell, obfuscation, etc.
```

## 📊 Ausgabeformate

### JSON (Standard)
Strukturierte Ausgabe für programmatische Verarbeitung:
```json
{
  "scan_time": "2024-01-15T10:30:00Z",
  "total_matches": 5,
  "file_results": [...]
}
```

### HTML
Interaktiver Report mit:
- Dashboard mit Statistiken
- Severity-Chart
- Filterbare Ergebnisliste
- Syntax-Highlighting
- Kontext-Anzeige

### CSV
Tabellarische Ausgabe für Excel/Analyse-Tools

### Text
Formatierter Plain-Text-Report

## 🔒 Built-in Malware-Signaturen

Wenn keine Pattern angegeben werden, verwendet CodeHunter automatisch eine Sammlung bekannter Malware-Signaturen:

- **PHP Backdoors**: Base64-encoded eval, gzinflate, shell_exec, etc.
- **Webshells**: FilesMan, WSO, c99, r57, b374k
- **Code Injection**: preg_replace /e, create_function, assert
- **File Operations**: Unsichere file_put_contents, include/require
- **Obfuscation**: Hex-encoding, chr()-Concatenation
- **JavaScript**: Packed code, fromCharCode-Obfuscation
- **Crypto Miners**: CoinHive und ähnliche

## ⚡ Performance-Tipps

1. **Einschränken der Extensions**: `--extensions php,js,html`
2. **Ignore-Patterns nutzen**: `--ignore "*.min.js" --ignore "vendor/"`
3. **Maximale Dateigröße setzen**: `--max-size 10MB`
4. **Threads anpassen**: `--threads 8`

## 🏗️ Kompilierung für maximale Performance

```bash
# Release-Build mit allen Optimierungen
cargo build --release

# Für noch mehr Speed (benötigt nightly):
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## 📜 Lizenz

MIT License

## 🤝 Entwickelt für

Security-Teams zur professionellen Analyse von:
- Gehackten Webseiten
- Kompromittierten Servern
- Code-Audits
- Malware-Analysen
