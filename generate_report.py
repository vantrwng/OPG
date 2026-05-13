import json
import os

def generate_html_report(json_file="beam_strategies.json", output_file="fuzzing_report.html"):
    if not os.path.exists(json_file):
        print(f"Error: {json_file} không tồn tại.")
        return

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary = data.get("summary", {})
    total_requests = summary.get("total_requests", 0)
    server_errors = summary.get("server_errors_500", 0)
    auth_anomalies = summary.get("auth_anomalies", 0)
    total_findings = summary.get("total_findings", 0)
    total_strategies = summary.get("total_strategies_found", 0)
    top_strategies = data.get("top_strategies", [])
    findings = data.get("findings", [])
    endpoint_stats = data.get("endpoint_stats", {})

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hybrid Stateful API Fuzzer Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0f172a;
            --surface-color: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-primary: #3b82f6;
            --accent-secondary: #8b5cf6;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(at 0% 0%, rgba(59, 130, 246, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(139, 92, 246, 0.15) 0px, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 2rem;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            margin-bottom: 3rem;
            animation: fadeInDown 0.8s ease-out;
        }}

        h1 {{
            font-size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
            letter-spacing: -1px;
        }}

        .stats-container {{
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-bottom: 3rem;
        }}

        .stat-card {{
            background: var(--surface-color);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 1.5rem 3rem;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            animation: fadeInUp 0.8s ease-out 0.2s both;
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: rgba(255, 255, 255, 0.2);
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--success);
        }}

        .stat-label {{
            color: var(--text-muted);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .strategies-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 1.5rem;
        }}

        .strategy-card {{
            background: var(--surface-color);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            animation: fadeIn 0.8s ease-out 0.4s both;
            position: relative;
            overflow: hidden;
        }}

        .strategy-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--accent-primary);
            transition: height 0.3s ease;
        }}

        .strategy-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.3);
            border-color: rgba(255, 255, 255, 0.1);
        }}

        .strategy-card:hover::before {{
            background: var(--accent-secondary);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .rank-badge {{
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .score-badge {{
            color: var(--warning);
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.3rem;
        }}

        .bucket-badge {{
            display: inline-block;
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 1rem;
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-muted);
        }}

        .chain-container {{
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}

        .api-node {{
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
        
        .api-node:last-child {{
            margin-bottom: 0;
        }}

        .api-node:not(:last-child)::after {{
            content: '↓';
            color: var(--accent-secondary);
            margin-left: 0.5rem;
            font-weight: bold;
        }}

        .state-container {{
            font-family: 'Fira Code', monospace;
            font-size: 0.75rem;
            color: var(--text-muted);
            background: rgba(0, 0, 0, 0.2);
            padding: 0.75rem;
            border-radius: 6px;
            border-left: 2px solid var(--success);
            word-break: break-all;
        }}

        @keyframes fadeInDown {{
            from {{ opacity: 0; transform: translateY(-20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        @keyframes fadeIn {{
            from {{ opacity: 0; }}
            to {{ opacity: 1; }}
        }}

        /* Staggered animation delays for grid items */
        .strategy-card:nth-child(1) {{ animation-delay: 0.1s; }}
        .strategy-card:nth-child(2) {{ animation-delay: 0.2s; }}
        .strategy-card:nth-child(3) {{ animation-delay: 0.3s; }}
        .strategy-card:nth-child(4) {{ animation-delay: 0.4s; }}
        .strategy-card:nth-child(5) {{ animation-delay: 0.5s; }}
        .strategy-card:nth-child(6) {{ animation-delay: 0.6s; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>API Security Fuzzer Results</h1>
            <p style="color: var(--text-muted); font-size: 1.1rem;">Hybrid Stateful Exploration Graph Analysis</p>
        </header>

        <div class="stats-container">
            <div class="stat-card">
                <div class="stat-number">{total_strategies}</div>
                <div class="stat-label">Total Attack Chains Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(top_strategies)}</div>
                <div class="stat-label">Unique Viable Strategies</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_findings}</div>
                <div class="stat-label">Vulnerabilities Found</div>
            </div>
        </div>

        <div class="strategies-grid">
"""

    for strategy in top_strategies:
        rank = strategy.get("rank", "-")
        score = strategy.get("score", 0)
        bucket = strategy.get("bucket", "unknown")
        depth = strategy.get("depth", 0)
        chain = strategy.get("chain", [])
        state = strategy.get("captured_state", {})

        chain_html = ""
        for idx, node in enumerate(chain):
            chain_html += f'<div class="api-node"><span style="color: #64748b; margin-right: 8px;">{idx+1}.</span> {node}</div>'

        state_html = ""
        if state:
            state_str = json.dumps(state, indent=2).replace('"', '&quot;')
            state_html = f'<div class="state-container"><strong>State Seeding:</strong><br><pre>{json.dumps(state, indent=2)}</pre></div>'
        else:
            state_html = f'<div class="state-container" style="border-left-color: #64748b; opacity: 0.6;">No specific state captured</div>'

        vulns = strategy.get("vulnerabilities", [])
        vuln_html = ""
        if vulns:
            vuln_html = '<div style="margin-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 1rem;">'
            vuln_html += '<div style="color: var(--danger); font-weight: 600; margin-bottom: 0.5rem; font-size: 0.9rem;">⚠️ Detected Vulnerabilities:</div>'
            for v in vulns:
                api_id = v.get('api_id', 'unknown')
                status = v.get('status', 0)
                details = v.get('details', [])
                
                status_color = "var(--danger)" if status >= 500 else "var(--warning)"
                
                details_list = "".join([f"<li style='margin-bottom: 2px;'>{d}</li>" for d in details])
                if not details_list:
                    details_list = "<li>No specific anomaly details provided.</li>"
                    
                vuln_html += f'''
                <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid {status_color}; padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; font-size: 0.85rem;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                        <span style="font-family: 'Fira Code', monospace; color: #f8fafc; font-weight: bold;">{api_id}</span>
                        <span style="color: {status_color}; font-weight: bold; background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 4px;">HTTP {status}</span>
                    </div>
                    <ul style="padding-left: 1.2rem; color: #cbd5e1; margin-top: 4px;">
                        {details_list}
                    </ul>
                </div>
                '''
            vuln_html += '</div>'

        card_html = f"""
            <div class="strategy-card">
                <div class="card-header">
                    <span class="rank-badge">Rank #{rank}</span>
                    <span class="score-badge">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                        {score} pts
                    </span>
                </div>
                <div class="bucket-badge">Bucket: {bucket} | Depth: {depth}</div>
                
                <div style="font-size: 0.9rem; margin-bottom: 0.5rem; color: var(--text-muted);">Attack Chain Workflow:</div>
                <div class="chain-container">
                    {chain_html}
                </div>
                
                {state_html}
                {vuln_html}
            </div>
        """
        html_content += card_html

    html_content += """
        </div>
    </div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"Report generated successfully at: {output_file}")

if __name__ == "__main__":
    generate_html_report()
