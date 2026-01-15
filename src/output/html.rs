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

    let html = generate_html(results);
    writer.write_all(html.as_bytes())?;
    writer.flush()?;

    Ok(())
}

fn generate_html(results: &ScanResults) -> String {
    let severity_data = format!(
        "[{}, {}, {}, {}, {}]",
        results.severity_summary.critical,
        results.severity_summary.high,
        results.severity_summary.medium,
        results.severity_summary.low,
        results.severity_summary.info
    );

    let mut findings_html = String::new();
    
    for file_result in &results.file_results {
        if file_result.matches.is_empty() {
            continue;
        }

        let max_severity = file_result
            .matches
            .iter()
            .map(|m| &m.severity)
            .max()
            .unwrap_or(&Severity::Info);

        let severity_class = match max_severity {
            Severity::Critical => "severity-critical",
            Severity::High => "severity-high",
            Severity::Medium => "severity-medium",
            Severity::Low => "severity-low",
            Severity::Info => "severity-info",
        };

        findings_html.push_str(&format!(
            r#"<div class="file-card {}">
                <div class="file-header" onclick="toggleFile(this)">
                    <span class="file-icon">📄</span>
                    <span class="file-path">{}</span>
                    <span class="match-count">{} match{}</span>
                    <span class="toggle-icon">▼</span>
                </div>
                <div class="file-content">
                    <div class="file-meta">
                        <span>Size: {} bytes</span>
                        <span>Encoding: {}</span>
                    </div>
                    <div class="matches">"#,
            severity_class,
            html_escape(&file_result.relative_path),
            file_result.matches.len(),
            if file_result.matches.len() == 1 { "" } else { "es" },
            file_result.file_size,
            html_escape(&file_result.encoding)
        ));

        for m in &file_result.matches {
            let severity_badge = match m.severity {
                Severity::Critical => r#"<span class="badge badge-critical">CRITICAL</span>"#,
                Severity::High => r#"<span class="badge badge-high">HIGH</span>"#,
                Severity::Medium => r#"<span class="badge badge-medium">MEDIUM</span>"#,
                Severity::Low => r#"<span class="badge badge-low">LOW</span>"#,
                Severity::Info => r#"<span class="badge badge-info">INFO</span>"#,
            };

            let pattern_name = m
                .pattern_name
                .as_ref()
                .map(|n| html_escape(n))
                .unwrap_or_else(|| html_escape(&m.pattern_original));

            let category = m
                .category
                .as_ref()
                .map(|c| format!(r#"<span class="category">{}</span>"#, html_escape(c)))
                .unwrap_or_default();

            findings_html.push_str(&format!(
                r#"<div class="match">
                    <div class="match-header">
                        {}
                        <span class="pattern-name">{}</span>
                        {}
                        <span class="location">Line {}, Col {}</span>
                    </div>
                    <div class="code-block">"#,
                severity_badge, pattern_name, category, m.line_number, m.column
            ));

            // Context before
            for (i, line) in m.context_before.iter().enumerate() {
                let line_num = m.line_number - m.context_before.len() + i;
                findings_html.push_str(&format!(
                    r#"<div class="code-line context"><span class="line-num">{}</span><span class="line-content">{}</span></div>"#,
                    line_num,
                    html_escape(line)
                ));
            }

            // Matched line with highlight
            let highlighted_line = highlight_match(&m.line_content, &m.matched_text);
            findings_html.push_str(&format!(
                r#"<div class="code-line matched"><span class="line-num">{}</span><span class="line-content">{}</span></div>"#,
                m.line_number,
                highlighted_line
            ));

            // Context after
            for (i, line) in m.context_after.iter().enumerate() {
                let line_num = m.line_number + 1 + i;
                findings_html.push_str(&format!(
                    r#"<div class="code-line context"><span class="line-num">{}</span><span class="line-content">{}</span></div>"#,
                    line_num,
                    html_escape(line)
                ));
            }

            findings_html.push_str("</div></div>");
        }

        findings_html.push_str("</div></div></div>");
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeHunter Scan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
            --accent: #238636;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 30px 0;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2.5rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        header h1::before {{
            content: '🔍';
            font-size: 2rem;
        }}

        .scan-meta {{
            margin-top: 15px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--info), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .charts-container {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}

        @media (max-width: 768px) {{
            .charts-container {{
                grid-template-columns: 1fr;
            }}
        }}

        .chart-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }}

        .chart-card h3 {{
            margin-bottom: 15px;
            font-size: 1.1rem;
        }}

        .severity-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 15px;
            justify-content: center;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
        }}

        .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .findings-section h2 {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .file-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 15px;
            overflow: hidden;
        }}

        .file-card.severity-critical {{
            border-left: 4px solid var(--critical);
        }}

        .file-card.severity-high {{
            border-left: 4px solid var(--high);
        }}

        .file-card.severity-medium {{
            border-left: 4px solid var(--medium);
        }}

        .file-card.severity-low {{
            border-left: 4px solid var(--low);
        }}

        .file-card.severity-info {{
            border-left: 4px solid var(--info);
        }}

        .file-header {{
            display: flex;
            align-items: center;
            padding: 15px 20px;
            cursor: pointer;
            transition: background 0.2s;
            gap: 10px;
        }}

        .file-header:hover {{
            background: var(--bg-tertiary);
        }}

        .file-icon {{
            font-size: 1.2rem;
        }}

        .file-path {{
            flex: 1;
            font-family: monospace;
            font-size: 0.95rem;
            word-break: break-all;
        }}

        .match-count {{
            background: var(--bg-tertiary);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .toggle-icon {{
            transition: transform 0.3s;
        }}

        .file-header.collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}

        .file-content {{
            border-top: 1px solid var(--border-color);
            padding: 20px;
            display: none;
        }}

        .file-content.show {{
            display: block;
        }}

        .file-meta {{
            display: flex;
            gap: 20px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 20px;
        }}

        .match {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
        }}

        .match-header {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }}

        .badge {{
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: black; }}
        .badge-low {{ background: var(--low); color: black; }}
        .badge-info {{ background: var(--info); color: white; }}

        .pattern-name {{
            font-weight: 600;
            color: var(--text-primary);
        }}

        .category {{
            background: var(--bg-secondary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .location {{
            margin-left: auto;
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-family: monospace;
        }}

        .code-block {{
            font-family: 'SF Mono', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }}

        .code-line {{
            display: flex;
            padding: 2px 15px;
        }}

        .code-line.context {{
            color: var(--text-secondary);
        }}

        .code-line.matched {{
            background: rgba(248, 81, 73, 0.15);
        }}

        .line-num {{
            min-width: 50px;
            color: var(--text-secondary);
            user-select: none;
            text-align: right;
            padding-right: 15px;
            border-right: 1px solid var(--border-color);
            margin-right: 15px;
        }}

        .line-content {{
            white-space: pre;
            overflow-x: auto;
        }}

        .highlight {{
            background: rgba(248, 81, 73, 0.4);
            padding: 1px 3px;
            border-radius: 3px;
            font-weight: 600;
        }}

        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }}

        .no-findings .icon {{
            font-size: 4rem;
            margin-bottom: 20px;
        }}

        .no-findings h3 {{
            color: var(--accent);
            margin-bottom: 10px;
        }}

        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
        }}

        .filter-bar {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 8px 16px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .filter-btn:hover,
        .filter-btn.active {{
            background: var(--info);
            border-color: var(--info);
        }}

        .search-box {{
            flex: 1;
            min-width: 200px;
            padding: 8px 16px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 6px;
            font-size: 0.9rem;
        }}

        .search-box::placeholder {{
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>CodeHunter Scan Report</h1>
            <div class="scan-meta">
                <strong>Target:</strong> {} | 
                <strong>Scan Time:</strong> {} | 
                <strong>Duration:</strong> {:.2}s
            </div>
        </div>
    </header>

    <main class="container">
        <div class="dashboard">
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Matches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Files with Matches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Bytes Processed</div>
            </div>
        </div>

        <div class="charts-container">
            <div class="chart-card">
                <h3>📊 Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
                <div class="severity-legend">
                    <div class="legend-item"><span class="legend-dot" style="background: var(--critical)"></span> Critical ({})</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--high)"></span> High ({})</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--medium)"></span> Medium ({})</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--low)"></span> Low ({})</div>
                    <div class="legend-item"><span class="legend-dot" style="background: var(--info)"></span> Info ({})</div>
                </div>
            </div>
            <div class="chart-card">
                <h3>📈 Statistics</h3>
                <canvas id="statsChart"></canvas>
            </div>
        </div>

        <section class="findings-section">
            <h2>🎯 Findings</h2>
            
            <div class="filter-bar">
                <input type="text" class="search-box" id="searchBox" placeholder="Search files..." onkeyup="filterFiles()">
                <button class="filter-btn active" onclick="filterBySeverity('all')">All</button>
                <button class="filter-btn" onclick="filterBySeverity('critical')">Critical</button>
                <button class="filter-btn" onclick="filterBySeverity('high')">High</button>
                <button class="filter-btn" onclick="filterBySeverity('medium')">Medium</button>
                <button class="filter-btn" onclick="filterBySeverity('low')">Low</button>
            </div>

            <div id="findings">
                {}
            </div>

            {}
        </section>
    </main>

    <footer>
        Generated by CodeHunter v1.0.0 | {} patterns used | Report generated at {}
    </footer>

    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: {},
                    backgroundColor: ['#f85149', '#ff7b72', '#d29922', '#3fb950', '#58a6ff'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                cutout: '60%'
            }}
        }});

        // Stats Chart
        const statsCtx = document.getElementById('statsChart').getContext('2d');
        new Chart(statsCtx, {{
            type: 'bar',
            data: {{
                labels: ['Files Scanned', 'Files w/ Matches', 'Binary Skipped', 'Errors'],
                datasets: [{{
                    data: [{}, {}, {}, {}],
                    backgroundColor: ['#58a6ff', '#d29922', '#8b949e', '#f85149'],
                    borderRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{ color: '#30363d' }},
                        ticks: {{ color: '#8b949e' }}
                    }},
                    x: {{
                        grid: {{ display: false }},
                        ticks: {{ color: '#8b949e' }}
                    }}
                }}
            }}
        }});

        function toggleFile(header) {{
            header.classList.toggle('collapsed');
            const content = header.nextElementSibling;
            content.classList.toggle('show');
        }}

        function filterFiles() {{
            const search = document.getElementById('searchBox').value.toLowerCase();
            document.querySelectorAll('.file-card').forEach(card => {{
                const path = card.querySelector('.file-path').textContent.toLowerCase();
                card.style.display = path.includes(search) ? 'block' : 'none';
            }});
        }}

        function filterBySeverity(severity) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            document.querySelectorAll('.file-card').forEach(card => {{
                if (severity === 'all') {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = card.classList.contains('severity-' + severity) ? 'block' : 'none';
                }}
            }});
        }}

        // Auto-expand first file with critical/high severity
        const firstCritical = document.querySelector('.severity-critical .file-header, .severity-high .file-header');
        if (firstCritical) {{
            toggleFile(firstCritical);
        }}
    </script>
</body>
</html>"##,
        html_escape(&results.target_path.to_string_lossy()),
        results.scan_time.format("%Y-%m-%d %H:%M:%S UTC"),
        results.duration_ms as f64 / 1000.0,
        results.total_files_scanned,
        results.total_matches,
        results.total_files_with_matches,
        format_bytes(results.total_bytes_scanned),
        results.severity_summary.critical,
        results.severity_summary.high,
        results.severity_summary.medium,
        results.severity_summary.low,
        results.severity_summary.info,
        findings_html,
        if results.total_matches == 0 {
            r#"<div class="no-findings">
                <div class="icon">✅</div>
                <h3>No suspicious patterns found</h3>
                <p>The scan completed without finding any matches for the specified patterns.</p>
            </div>"#
        } else {
            ""
        },
        results.patterns_used,
        results.scan_time.format("%Y-%m-%d %H:%M:%S UTC"),
        severity_data,
        results.total_files_scanned,
        results.total_files_with_matches,
        results.files_skipped_binary,
        results.files_with_errors
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn highlight_match(line: &str, matched: &str) -> String {
    let escaped_line = html_escape(line);
    let escaped_matched = html_escape(matched);
    
    escaped_line.replace(
        &escaped_matched,
        &format!(r#"<span class="highlight">{}</span>"#, escaped_matched),
    )
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
