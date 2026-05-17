import json
import os
import html

def generate_html_report(json_file="beam_strategies.json", output_dir="fuzzing_report"):
    if not os.path.exists(json_file):
        print(f"Error: {json_file} không tồn tại.")
        return

    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "index.html")

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

    # ---------- GENERATE API DETAIL PAGES ----------
    for api, stats in endpoint_stats.items():
        api_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Details - {html.escape(api)}</title>
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
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        a.back-btn {{
            display: inline-block;
            margin-bottom: 2rem;
            color: var(--accent-primary);
            text-decoration: none;
            font-weight: 600;
        }}
        a.back-btn:hover {{ text-decoration: underline; }}
        h1 {{ margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem; }}
        .status-section {{
            background: var(--surface-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        pre {{
            background: rgba(0,0,0,0.4);
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            color: #e2e8f0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="index.html" class="back-btn">&larr; Quay lại Dashboard</a>
        <h1>API: <span style="font-family: 'Fira Code', monospace; color: var(--accent-primary);">{api}</span></h1>
        
        <p>Tổng số lần gọi: <strong>{stats.get('visits', 0)}</strong></p>
        
        <h2 style="margin-top: 2rem; margin-bottom: 1rem;">Lịch sử các lần Request/Response</h2>
"""
        all_requests = stats.get("all_requests", [])
        
        if not all_requests:
            api_html += "<p style='color: var(--text-muted);'>Chưa có dữ liệu lịch sử nào được ghi lại (có thể API này fuzzer chưa quét tới hoặc chưa được cập nhật code ghi nhận lịch sử).</p>"
        else:
            for i, req in enumerate(all_requests):
                method_str = req.get("method", "GET").upper()
                path_str   = req.get("path", "/")
                status_str = req.get("status", "0")
                payload_source = req.get("payload_source", "NONE")
                request_payload = req.get("request_payload", {})
                response_text = req.get("response_text", "")
                repair_reason = req.get("repair_reason", "")
                repair_history = req.get("repair_history", [])
                
                status_int = int(status_str)
                if status_int >= 500: color = "var(--danger)"
                elif status_int >= 400: color = "var(--warning)"
                else: color = "var(--success)"

                safe_req = html.escape(json.dumps(request_payload, indent=2, ensure_ascii=False))

                safe_resp = html.escape(str(response_text))
                try:
                    parsed_json = json.loads(response_text)
                    safe_resp = html.escape(json.dumps(parsed_json, indent=2, ensure_ascii=False))
                except Exception:
                    pass
                
                source_badge = ""
                if payload_source == "LLM_REPAIR":
                    source_badge = "<span style='background: #f59e0b; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px; font-family: Inter;'>🛠️ LLM Repaired</span>"
                elif payload_source == "LLM":
                    source_badge = "<span style='background: #8b5cf6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px; font-family: Inter;'>🤖 LLM Generated</span>"
                elif payload_source == "HEURISTIC":
                    source_badge = "<span style='background: #3b82f6; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin-left: 10px; font-family: Inter;'>⚡ Heuristic</span>"

                repair_html = ""
                if repair_reason:
                    history_items = ""
                    for hist in repair_history:
                        h_payload = html.escape(json.dumps(hist.get("payload", {}), indent=2, ensure_ascii=False))
                        
                        h_resp_raw = str(hist.get("response", ""))
                        try:
                            h_resp_raw = json.dumps(json.loads(h_resp_raw), indent=2, ensure_ascii=False)
                        except:
                            pass
                        h_resp = html.escape(h_resp_raw)
                        h_status = hist.get("status", "Unknown")
                        h_attempt = hist.get("attempt", 1)
                        
                        history_items += f"""
                        <div style="margin-top: 1rem; padding: 1rem; background: rgba(0,0,0,0.2); border-left: 3px solid #6b7280; border-radius: 4px;">
                            <h5 style="color: #9ca3af; margin-bottom: 0.5rem;">🚧 Attempt #{h_attempt} Failed (HTTP {h_status})</h5>
                            <div style="display: flex; gap: 1rem;">
                                <div style="flex: 1;">
                                    <div style="font-size: 0.75rem; color: #6b7280; margin-bottom: 0.25rem;">Sent Payload:</div>
                                    <pre style="margin:0; padding: 0.5rem; font-size: 0.8rem; background: #1f2937; border-radius: 4px;">{h_payload}</pre>
                                </div>
                                <div style="flex: 1;">
                                    <div style="font-size: 0.75rem; color: #6b7280; margin-bottom: 0.25rem;">Error Response:</div>
                                    <pre style="margin:0; padding: 0.5rem; font-size: 0.8rem; background: #372f2f; color: #fca5a5; border-radius: 4px;">{h_resp}</pre>
                                </div>
                            </div>
                        </div>
                        """
                        
                    repair_html = f"""
                    <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 0.75rem; margin-bottom: 1rem; font-size: 0.85rem; color: #b45309; border-radius: 0 4px 4px 0;">
                        <strong>⚠️ {html.escape(repair_reason)}</strong>
                        {history_items}
                    </div>
                    """

                api_html += f"""
                <div class="status-section" style="border-left: 4px solid {color}; margin-bottom: 2rem;">
                    <h3 style="color: {color}; margin-bottom: 1rem; font-family: monospace;">
                        Lần gọi #{i+1} — {method_str} {path_str} — HTTP {status_str} {source_badge}
                    </h3>
                    
                    {repair_html}
                    
                    <h4 style="color: var(--text-main); margin-bottom: 0.5rem; font-size: 0.9rem;">📥 Request Payload</h4>
                    <pre style="margin-bottom: 1rem; border: 1px solid rgba(255,255,255,0.1);">{safe_req}</pre>
                    
                    <h4 style="color: var(--text-main); margin-bottom: 0.5rem; font-size: 0.9rem;">📤 Response Body</h4>
                    <pre style="border: 1px solid rgba(255,255,255,0.1);">{safe_resp}</pre>
                </div>
                """
        api_html += """
    </div>
</body>
</html>
"""
        with open(os.path.join(output_dir, f"api_{api}.html"), "w", encoding="utf-8") as f:
            f.write(api_html)


    # ---------- GENERATE INDEX.HTML ----------
    success_apis = []
    failed_apis = []
    error_500_apis = []

    for api, stats in endpoint_stats.items():
        status_counts = stats.get("status_counts", {})
        has_2xx = any(str(code).startswith('2') for code in status_counts.keys())
        has_500 = '500' in [str(code) for code in status_counts.keys()]
        
        if has_500:
            error_500_apis.append(api)
        elif has_2xx:
            success_apis.append(api)
        else:
            failed_apis.append(api)

    def make_badges(api_list, bg_color):
        if not api_list:
            return "<span style='color: var(--text-muted); font-size: 0.9rem;'>Không có API nào</span>"
        return "".join([f"<a href='api_{api}.html' style='background: {bg_color}; color: #fff; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-family: monospace; text-decoration: none; transition: opacity 0.2s;' onmouseover='this.style.opacity=0.8' onmouseout='this.style.opacity=1'>{api}</a>" for api in api_list])

    success_badges = make_badges(success_apis, "var(--success)")
    failed_badges = make_badges(failed_apis, "var(--warning)")
    error_500_badges = make_badges(error_500_apis, "var(--danger)")

    top_strategies = sorted(top_strategies, key=lambda x: x.get("score", 0), reverse=True)

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
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
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
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ text-align: center; margin-bottom: 3rem; animation: fadeInDown 0.8s ease-out; }}
        h1 {{ font-size: 3rem; font-weight: 800; background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0.5rem; letter-spacing: -1px; }}
        .stats-container {{ display: flex; justify-content: center; gap: 2rem; margin-bottom: 3rem; }}
        .stat-card {{ background: var(--surface-color); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; padding: 1.5rem 3rem; text-align: center; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2); animation: fadeInUp 0.8s ease-out 0.2s both; transition: transform 0.3s ease; }}
        .stat-card:hover {{ transform: translateY(-5px); border-color: rgba(255, 255, 255, 0.2); }}
        .stat-number {{ font-size: 2.5rem; font-weight: 800; color: var(--success); }}
        .stat-label {{ color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }}
        .strategies-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 1.5rem; }}
        .strategy-card {{ background: var(--surface-color); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; padding: 1.5rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); transition: all 0.3s ease; animation: fadeIn 0.8s ease-out 0.4s both; position: relative; overflow: hidden; }}
        .strategy-card::before {{ content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent-primary); transition: height 0.3s ease; }}
        .strategy-card:hover {{ transform: translateY(-5px); box-shadow: 0 12px 24px rgba(0, 0, 0, 0.3); border-color: rgba(255, 255, 255, 0.1); }}
        .strategy-card:hover::before {{ background: var(--accent-secondary); }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }}
        .rank-badge {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }}
        .score-badge {{ color: var(--warning); font-weight: 600; font-size: 0.9rem; display: flex; align-items: center; gap: 0.3rem; }}
        .bucket-badge {{ display: inline-block; font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; font-weight: 600; margin-bottom: 1rem; background: rgba(255, 255, 255, 0.1); color: var(--text-muted); }}
        .chain-container {{ background: rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
        .api-node {{ font-family: 'Fira Code', monospace; font-size: 0.85rem; color: #e2e8f0; display: flex; align-items: center; margin-bottom: 0.5rem; }}
        .api-node:last-child {{ margin-bottom: 0; }}
        .api-node:not(:last-child)::after {{ content: '↓'; color: var(--accent-secondary); margin-left: 0.5rem; font-weight: bold; }}
        .state-container {{ font-family: 'Fira Code', monospace; font-size: 0.75rem; color: var(--text-muted); background: rgba(0, 0, 0, 0.2); padding: 0.75rem; border-radius: 6px; border-left: 2px solid var(--success); word-break: break-all; }}
        
        @keyframes fadeInDown {{ from {{ opacity: 0; transform: translateY(-20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        @keyframes fadeInUp {{ from {{ opacity: 0; transform: translateY(20px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
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
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem;">Click vào các API bên dưới hoặc trong Attack Chains để xem chi tiết response trả về.</p>
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

        <h1 style="font-size: 2.5rem; margin-bottom: 0.5rem; font-family: 'Fira Code', monospace; word-break: break-all;">
            {html.escape(api)}
        </h1>

        <div class="api-stats-section" style="margin-bottom: 3rem;">
            <h2 style="font-size: 1.8rem; margin-bottom: 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem;">Thống kê Fuzzing API</h2>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                <!-- Success APIs -->
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--success); border-radius: 12px; padding: 1.5rem;">
                    <h3 style="color: var(--success); margin-bottom: 1rem; display: flex; justify-content: space-between;">
                        <span>✅ Thành công</span>
                        <span>{len(success_apis)} APIs</span>
                    </h3>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        {success_badges}
                    </div>
                </div>

                <!-- Failed APIs -->
                <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid var(--warning); border-radius: 12px; padding: 1.5rem;">
                    <h3 style="color: var(--warning); margin-bottom: 1rem; display: flex; justify-content: space-between;">
                        <span>⚠️ Thất bại</span>
                        <span>{len(failed_apis)} APIs</span>
                    </h3>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        {failed_badges}
                    </div>
                </div>

                <!-- 500 APIs -->
                <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 12px; padding: 1.5rem;">
                    <h3 style="color: var(--danger); margin-bottom: 1rem; display: flex; justify-content: space-between;">
                        <span>💥 Lỗi 500</span>
                        <span>{len(error_500_apis)} APIs</span>
                    </h3>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        {error_500_badges}
                    </div>
                </div>
            </div>
        </div>

        <h2 style="font-size: 1.8rem; margin-bottom: 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem;">Top Attack Chains</h2>

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
            chain_html += f'<div class="api-node"><span style="color: #64748b; margin-right: 8px;">{idx+1}.</span> <a href="api_{node}.html" style="color: #e2e8f0; text-decoration: none; border-bottom: 1px dashed #64748b; transition: color 0.2s;" onmouseover="this.style.color=\'#60a5fa\'" onmouseout="this.style.color=\'#e2e8f0\'">{node}</a></div>'

        state_html = ""
        if state:
            state_html = f'<div class="state-container"><strong>State Seeding:</strong><br><pre>{json.dumps(state, indent=2)}</pre></div>'
        else:
            state_html = f'<div class="state-container" style="border-left-color: #64748b; opacity: 0.6;">No specific state captured</div>'

        vulns = strategy.get("vulnerabilities", [])
        vuln_html = ""
        if vulns:
            vuln_html = '<div style="margin-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 1rem;">'
            vuln_html += '<div style="color: var(--danger); font-weight: 600; margin-bottom: 0.5rem; font-size: 0.9rem;">⚠️ Detected Vulnerabilities:</div>'
            for v in vulns:
                api_id = v.get('api_id', v.get('api', 'unknown'))
                status = v.get('status', 0)
                details = v.get('details', [])
                
                status_color = "var(--danger)" if status >= 500 else "var(--warning)"
                
                details_list = "".join([f"<li style='margin-bottom: 2px;'>{d}</li>" for d in details])
                if not details_list:
                    details_list = "<li>No specific anomaly details provided.</li>"
                    
                vuln_html += f'''
                <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid {status_color}; padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; font-size: 0.85rem;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                        <a href="api_{api_id}.html" style="font-family: 'Fira Code', monospace; color: #f8fafc; font-weight: bold; text-decoration: none; border-bottom: 1px dashed #f8fafc;">{api_id}</a>
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
    
    print(f"Report generated successfully at: {output_dir}/")

if __name__ == "__main__":
    generate_html_report()
