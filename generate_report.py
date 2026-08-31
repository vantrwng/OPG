"""
generate_report.py
==================
Tạo báo cáo HTML dashboard cho kết quả fuzzing.
Toàn bộ giao diện hiển thị bằng tiếng Việt.
"""

import json
import os
import html
from datetime import datetime


# ── Hàm hỗ trợ ───────────────────────────────────────────────────────────────

def _esc(s) -> str:
    return html.escape(str(s))


def _status_color(status: int) -> str:
    if status >= 500: return "#ef4444"
    if status >= 400: return "#f59e0b"
    if status >= 200: return "#10b981"
    return "#94a3b8"


def _source_badge(payload_source: str) -> str:
    src = (payload_source or "").upper()
    VI_LABELS = {
        "OLLAMA_ARCHITECT":           ("#8b5cf6", "🤖 Ollama Kiến trúc"),
        "HEURISTIC":                  ("#3b82f6", "⚡ Heuristic"),
        "LLM_REPAIR":                 ("#f59e0b", "🛠️ Tự sửa lỗi"),
        "NONE":                       ("",        ""),
        "ATTACKER_ID_SUBSTITUTION":   ("#dc2626", "🔴 Thay ID"),
        "ATTACKER_PARAM_POLLUTION":   ("#d97706", "🟠 Nhồi tham số"),
        "ATTACKER_REFERENCE_FORGE":   ("#7c3aed", "🟣 Giả mạo tham chiếu"),
    }
    if src in VI_LABELS:
        color, label = VI_LABELS[src]
        if not label:
            return ""
        return (
            f"<span style='background:{color};color:#fff;padding:2px 8px;"
            f"border-radius:4px;font-size:0.78rem;margin-left:8px'>{label}</span>"
        )
    if src.startswith("ATTACKER_"):
        tag = src.replace("ATTACKER_", "").replace("_", " ").title()
        return (
            f"<span style='background:#dc2626;color:#fff;padding:2px 8px;"
            f"border-radius:4px;font-size:0.78rem;margin-left:8px'>🔴 {tag}</span>"
        )
    if "LLM" in src:
        return (
            "<span style='background:#8b5cf6;color:#fff;padding:2px 8px;"
            "border-radius:4px;font-size:0.78rem;margin-left:8px'>🤖 LLM</span>"
        )
    return ""


def _severity_vi(severity: str) -> str:
    s = (severity or "").upper()
    if s == "HIGH":   return "Cao"
    if s == "MEDIUM": return "Trung bình"
    if s == "LOW":    return "Thấp"
    return severity


def _severity_color(severity: str) -> str:
    s = (severity or "").upper()
    if s == "HIGH":   return "#ef4444"
    if s == "MEDIUM": return "#f59e0b"
    if s == "LOW":    return "#10b981"
    return "#94a3b8"


def _bola_type_vi(bola_type: str) -> str:
    t = (bola_type or "").lower()
    if "data_exposure"        in t: return "Lộ dữ liệu người khác"
    if "auth_bypass"          in t: return "Vượt xác thực"
    if "privilege_escalation" in t: return "Leo thang đặc quyền"
    if "none"                 in t: return ""
    return bola_type


def _finding_type_vi(ftype: str) -> str:
    t = (ftype or "").upper()
    if "DATA_EXPOSURE"        in t: return "BOLA — Lộ dữ liệu"
    if "AUTH_BYPASS"          in t: return "BOLA — Vượt xác thực"
    if "PRIVILEGE_ESCALATION" in t: return "BOLA — Leo thang đặc quyền"
    if "BOLA"                 in t or "IDOR" in t: return "BOLA/IDOR"
    if "CRASH"                in t or "500"  in t: return "Crash / Lỗi 500"
    if "AUTH"                 in t: return "Bất thường xác thực"
    return ftype


def _finding_icon(ftype: str) -> str:
    t = (ftype or "").upper()
    if "BOLA" in t or "IDOR" in t: return "🔓"
    if "CRASH" in t or "500" in t: return "💥"
    if "AUTH"  in t:                return "🔑"
    if "PRIVILEGE" in t:            return "👑"
    return "⚠️"


def _strategy_vi(strategy: str) -> str:
    s = (strategy or "").lower()
    if "id_substitution"  in s: return "Thay thế ID"
    if "param_pollution"  in s: return "Nhồi tham số"
    if "reference_forge"  in s: return "Giả mạo tham chiếu"
    if "mass_assignment"  in s: return "Mass Assignment"
    return strategy


# ── Bảng tóm tắt lỗ hổng ──────────────────────────────────────────────────────

def _build_vuln_summary_table(findings: list) -> str:
    """Bảng liệt kê gọn: lỗ hổng nào, tìm được ở API nào."""
    bola = [f for f in findings if "BOLA" in str(f.get("type","")).upper()
                                 or "IDOR" in str(f.get("type","")).upper()]
    if not bola:
        return (
            "<div style='background:rgba(16,185,129,0.08);border:1px solid #10b981;"
            "border-radius:10px;padding:1.5rem;text-align:center;"
            "color:#10b981;font-size:1rem;margin-bottom:1.5rem'>"
            "✅ Không phát hiện lỗ hổng BOLA/IDOR nào</div>"
        )

    rows = ""
    for i, f in enumerate(bola, 1):
        sev      = f.get("severity", "HIGH")
        sev_vi   = _severity_vi(sev)
        sev_col  = _severity_color(sev)
        ftype    = _finding_type_vi(f.get("type", ""))
        api      = f.get("api", f.get("api_id", ""))
        method   = f.get("method", "")
        path     = f.get("path", "")
        status   = f.get("status", 0)
        strat    = _strategy_vi(f.get("strategy", ""))
        conf     = int(float(f.get("confidence", 0)) * 100)
        desc     = f.get("description", "")

        strat_badge = ""
        if strat:
            strat_badge = (
                f"<span style='background:rgba(220,38,38,0.15);color:#fca5a5;"
                f"border:1px solid rgba(220,38,38,0.3);padding:1px 7px;"
                f"border-radius:4px;font-size:0.75rem;margin-left:6px'>{_esc(strat)}</span>"
            )

        rows += f"""
<tr style="border-bottom:1px solid rgba(255,255,255,0.06)">
  <td style="padding:0.75rem 0.5rem;text-align:center;color:#94a3b8;font-size:0.85rem">{i}</td>
  <td style="padding:0.75rem 0.5rem">
    <span style="color:{sev_col};font-weight:700;font-size:0.85rem">{_esc(ftype)}</span>
    {strat_badge}
  </td>
  <td style="padding:0.75rem 0.5rem;font-family:'Fira Code',monospace;font-size:0.82rem;color:#e2e8f0">
    <a href="javascript:void(0)" onclick="showApi('{_esc(api)}')"
       style="color:#60a5fa;text-decoration:none;border-bottom:1px dashed #3b82f6">
      {_esc(api)}
    </a><br>
    <span style="color:#64748b;font-size:0.75rem">{_esc(method)} {_esc(path)}</span>
  </td>
  <td style="padding:0.75rem 0.5rem;text-align:center">
    <span style="color:{_status_color(int(status) if str(status).isdigit() else 0)};
          font-weight:700;font-size:0.85rem;font-family:monospace">HTTP {status}</span>
  </td>
  <td style="padding:0.75rem 0.5rem;text-align:center">
    <span style="background:{sev_col}22;color:{sev_col};border:1px solid {sev_col};
          padding:2px 8px;border-radius:4px;font-size:0.78rem;font-weight:700">{_esc(sev_vi)}</span>
  </td>
  <td style="padding:0.75rem 0.5rem;text-align:center">
    <div style="background:rgba(255,255,255,0.08);border-radius:4px;height:6px;width:80px;
         display:inline-block;vertical-align:middle">
      <div style="background:{sev_col};height:6px;border-radius:4px;width:{conf}%"></div>
    </div>
    <span style="color:#94a3b8;font-size:0.75rem;margin-left:4px">{conf}%</span>
  </td>
</tr>
{"" if not desc else f"<tr style='border-bottom:1px solid rgba(255,255,255,0.04)'><td colspan=6 style='padding:0 0.5rem 0.75rem 3.5rem;color:#94a3b8;font-size:0.8rem;font-style:italic'>{_esc(desc)}</td></tr>"}"""

    return f"""
<div style="margin-bottom:2rem">
  <h3 style="font-size:1.1rem;color:#ef4444;margin-bottom:1rem">
    🔓 Danh sách lỗ hổng BOLA/IDOR ({len(bola)} phát hiện)
  </h3>
  <div style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:rgba(0,0,0,0.3);border-bottom:2px solid rgba(255,255,255,0.1)">
          <th style="padding:0.6rem 0.5rem;color:#64748b;font-size:0.75rem;text-align:center;font-weight:600">#</th>
          <th style="padding:0.6rem 0.5rem;color:#64748b;font-size:0.75rem;text-align:left;font-weight:600">Loại lỗ hổng</th>
          <th style="padding:0.6rem 0.5rem;color:#64748b;font-size:0.75rem;text-align:left;font-weight:600">API bị ảnh hưởng</th>
          <th style="padding:0.6rem 0.5rem;color:#64748b;font-size:0.75rem;text-align:center;font-weight:600">HTTP Status</th>
          <th style="padding:0.6rem 0.5rem;color:#64748b;font-size:0.75rem;text-align:center;font-weight:600">Mức độ</th>
          <th style="padding:0.6rem 0.5rem;color:#64748b;font-size:0.75rem;text-align:center;font-weight:600">Độ tin cậy</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>"""


# ── Chi tiết từng lỗ hổng ─────────────────────────────────────────────────────

def _build_findings_section(findings: list) -> str:
    if not findings:
        return (
            "<div style='background:rgba(16,185,129,0.08);border:1px solid #10b981;"
            "border-radius:12px;padding:2rem;text-align:center;color:#10b981;font-size:1.1rem'>"
            "✅ Không phát hiện lỗ hổng nào</div>"
        )

    bola_findings  = [f for f in findings if "BOLA" in str(f.get("type","")).upper()
                                          or "IDOR" in str(f.get("type","")).upper()]
    crash_findings = [f for f in findings if "CRASH" in str(f.get("type","")).upper()
                                          or "500"  in str(f.get("type","")).upper()]
    other_findings = [f for f in findings if f not in bola_findings and f not in crash_findings]

    def _card(f: dict) -> str:
        ftype      = _finding_type_vi(f.get("type", ""))
        severity   = f.get("severity", "HIGH")
        sev_vi     = _severity_vi(severity)
        confidence = f.get("confidence", 1.0)
        api        = f.get("api", f.get("api_id", ""))
        method     = f.get("method", "")
        path       = f.get("path", "")
        status     = f.get("status", 0)
        strategy   = _strategy_vi(f.get("strategy", ""))
        btype_vi   = _bola_type_vi(f.get("bola_type", f.get("type", "")))
        desc       = f.get("description", "")
        reasoning  = f.get("reasoning", "")
        evidence   = f.get("evidence", f.get("details", []))
        chain      = f.get("chain", [])

        sev_col  = _severity_color(severity)
        icon     = _finding_icon(f.get("type", ""))
        conf_pct = int(float(confidence) * 100)

        ev_items = "".join(
            f"<li style='margin-bottom:4px;color:#cbd5e1'>{_esc(e)}</li>"
            for e in (evidence or [])[:8]
        )
        if not ev_items:
            ev_items = "<li style='color:#64748b'>Không có bằng chứng cụ thể</li>"

        reasoning_html = ""
        if reasoning:
            reasoning_html = (
                f"<div style='margin-top:0.75rem;padding:0.75rem;background:rgba(59,130,246,0.1);"
                f"border-left:3px solid #3b82f6;border-radius:0 4px 4px 0;font-size:0.85rem;color:#cbd5e1'>"
                f"<strong style='color:#60a5fa'>💡 Lý do phát hiện (AI Phân tích):</strong><br>{_esc(reasoning)}"
                f"</div>"
            )

        chain_html = ""
        if chain:
            nodes = " → ".join(
                f"<code style='color:#94a3b8'>{_esc(n)}</code>" for n in chain
            )
            chain_html = (
                f"<div style='margin-top:0.75rem;font-size:0.8rem;color:#64748b'>"
                f"Chuỗi tấn công: {nodes}</div>"
            )

        strat_badge = ""
        if strategy:
            strat_badge = (
                f"<span style='background:rgba(220,38,38,0.2);color:#fca5a5;"
                f"padding:2px 8px;border-radius:4px;font-size:0.78rem;margin-left:8px'>"
                f"Chiến lược: {_esc(strategy)}</span>"
            )

        conf_bar = (
            f"<div style='margin-top:0.5rem;background:rgba(255,255,255,0.1);"
            f"border-radius:4px;height:4px;width:100%'>"
            f"<div style='background:{sev_col};height:4px;border-radius:4px;"
            f"width:{conf_pct}%'></div></div>"
            f"<div style='font-size:0.75rem;color:#94a3b8;margin-top:2px'>Độ tin cậy: {conf_pct}%</div>"
        )

        return f"""
<div style="background:rgba(30,41,59,0.8);border:1px solid rgba(255,255,255,0.08);
     border-left:4px solid {sev_col};border-radius:12px;padding:1.5rem;margin-bottom:1rem">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.75rem">
    <div>
      <span style="font-size:1.2rem">{icon}</span>
      <strong style="color:{sev_col};font-size:1rem;margin-left:6px">{_esc(ftype)}</strong>
      <span style="background:rgba(255,255,255,0.1);color:{sev_col};padding:2px 8px;
            border-radius:4px;font-size:0.75rem;margin-left:8px;font-weight:700">Mức độ: {_esc(sev_vi)}</span>
      {strat_badge}
    </div>
    <span style="color:{_status_color(int(status) if str(status).isdigit() else 0)};
          font-family:monospace;font-size:0.9rem;font-weight:700">HTTP {status}</span>
  </div>

  <div style="font-family:'Fira Code',monospace;font-size:0.88rem;color:#e2e8f0;margin-bottom:0.5rem">
    <span style="color:#64748b">{_esc(method)}</span>
    &nbsp;<a href="javascript:void(0)" onclick="showApi('{_esc(api)}')"
       style="color:#60a5fa;text-decoration:none;border-bottom:1px dashed #3b82f6">{_esc(api)}</a>
    {"&nbsp;— " + _esc(path) if path else ""}
  </div>

  {conf_bar}
  {"<p style='color:#94a3b8;font-size:0.85rem;margin-top:0.75rem'>" + _esc(desc) + "</p>" if desc else ""}
  {reasoning_html}

  <details style="margin-top:0.75rem">
    <summary style="cursor:pointer;color:#60a5fa;font-size:0.85rem;user-select:none">
      Bằng chứng ({len(evidence or [])} mục)
    </summary>
    <ul style="margin-top:0.5rem;padding-left:1.2rem;font-size:0.82rem">{ev_items}</ul>
  </details>
  {chain_html}
</div>"""

    tabs_html = ""
    panels_html = ""
    tab_groups = [
        ("bola",  f"🔓 BOLA/IDOR ({len(bola_findings)})",      bola_findings,  "#ef4444"),
        ("crash", f"💥 Crash/Lỗi 500 ({len(crash_findings)})", crash_findings, "#f97316"),
        ("other", f"⚠️ Khác ({len(other_findings)})",            other_findings, "#f59e0b"),
    ]
    first = True
    for tid, label, items, color in tab_groups:
        active_tab   = "1" if first else "0"
        display_panel= "block" if first else "none"
        bg = color if first else "rgba(255,255,255,0.08)"
        fg = "#fff" if first else "#94a3b8"
        tabs_html += (
            f"<button id='ftab_{tid}' onclick='switchFindingTab(\"{tid}\")'  "
            f"style='padding:0.4rem 1rem;border:none;border-radius:6px;cursor:pointer;"
            f"font-size:0.85rem;margin-right:0.5rem;background:{bg};color:{fg};"
            f"transition:all 0.2s'>{label}</button>"
        )
        cards = "".join(_card(f) for f in items) if items else (
            "<p style='color:#64748b;text-align:center;padding:1rem'>Không có lỗ hổng trong nhóm này</p>"
        )
        panels_html += f"<div id='fpanel_{tid}' style='display:{display_panel}'>{cards}</div>"
        first = False

    return f"""
<div style='margin-bottom:1rem'>{tabs_html}</div>
{panels_html}
<script>
function switchFindingTab(tid) {{
  ['bola','crash','other'].forEach(function(t) {{
    document.getElementById('fpanel_' + t).style.display = t === tid ? 'block' : 'none';
    var btn = document.getElementById('ftab_' + t);
    if (t === tid) {{
      btn.style.background = t === 'bola' ? '#ef4444' : t === 'crash' ? '#f97316' : '#f59e0b';
      btn.style.color = '#fff';
    }} else {{
      btn.style.background = 'rgba(255,255,255,0.08)';
      btn.style.color = '#94a3b8';
    }}
  }});
}}
</script>"""


# ── Chi tiết từng API ─────────────────────────────────────────────────────────

def _build_api_detail(api: str, stats: dict) -> str:
    escaped_api   = _esc(api)
    all_requests  = stats.get("all_requests", [])
    visits        = stats.get("visits", 0)
    status_counts = stats.get("status_counts", {})

    status_pills = " ".join(
        f"<span style='background:{_status_color(int(k) if k.isdigit() else 0)}22;"
        f"color:{_status_color(int(k) if k.isdigit() else 0)};"
        f"border:1px solid {_status_color(int(k) if k.isdigit() else 0)};"
        f"padding:2px 8px;border-radius:4px;font-size:0.8rem;font-family:monospace'>"
        f"HTTP {k}: {v} lần</span>"
        for k, v in sorted(status_counts.items())
    )

    requests_html = ""
    if not all_requests:
        requests_html = "<p style='color:#64748b'>Chưa có lịch sử request.</p>"
    else:
        for i, req in enumerate(all_requests):
            method     = req.get("method", "GET").upper()
            path       = req.get("path", "/")
            status_str = str(req.get("status", "0"))
            status_int = int(status_str) if status_str.isdigit() else 0
            src        = req.get("payload_source", "NONE")
            payload    = req.get("request_payload", {})
            resp_text  = req.get("response_text", "")
            headers    = req.get("sent_headers", {})
            chain      = req.get("chain", [])
            repair_rsn = req.get("repair_reason", "")
            repair_hist= req.get("repair_history", [])

            scolor = _status_color(status_int)
            badge  = _source_badge(src)

            # Ẩn token
            headers_display = {}
            for k, v in headers.items():
                if k.lower() == "authorization" and isinstance(v, str) and len(v) > 15:
                    parts = v.split(" ", 1)
                    tok = parts[1] if len(parts) > 1 else v
                    headers_display[k] = (
                        f"{parts[0]} {tok[:5]}...{tok[-5:]}"
                        if len(parts) > 1 else f"{tok[:5]}...{tok[-5:]}"
                    )
                else:
                    headers_display[k] = v
            safe_headers = _esc(json.dumps(headers_display, indent=2, ensure_ascii=False))

            safe_payload = _esc(json.dumps(payload, indent=2, ensure_ascii=False))
            try:
                safe_resp = _esc(json.dumps(json.loads(resp_text), indent=2, ensure_ascii=False))
            except Exception:
                safe_resp = _esc(str(resp_text))

            # Chuỗi tấn công
            chain_display = ""
            if chain:
                nodes = " → ".join(
                    f"<span style='color:#e2e8f0'>{_esc(n)}</span>" for n in chain
                )
                chain_display = (
                    f"<div style='background:rgba(0,0,0,0.3);border-radius:6px;padding:0.6rem;"
                    f"margin-bottom:0.75rem;font-family:monospace;font-size:0.82rem;color:#94a3b8'>"
                    f"📍 Chuỗi: {nodes}</div>"
                )

            # Lịch sử sửa lỗi
            repair_html = ""
            if repair_rsn:
                hist_items = ""
                for h in repair_hist:
                    h_payload = _esc(json.dumps(h.get("payload", {}), indent=2, ensure_ascii=False))
                    try:
                        h_resp = _esc(json.dumps(
                            json.loads(str(h.get("response", ""))), indent=2, ensure_ascii=False
                        ))
                    except Exception:
                        h_resp = _esc(str(h.get("response", "")))
                    hist_items += (
                        f"<div style='margin-top:0.75rem;padding:0.75rem;background:rgba(0,0,0,0.2);"
                        f"border-left:3px solid #6b7280;border-radius:4px'>"
                        f"<div style='color:#9ca3af;font-size:0.8rem;margin-bottom:0.4rem'>"
                        f"🚧 Lần thử #{h.get('attempt',1)} — HTTP {h.get('status','?')}</div>"
                        f"<div style='display:flex;gap:1rem;flex-wrap:wrap'>"
                        f"<div style='flex:1;min-width:280px'>"
                        f"<div style='font-size:0.72rem;color:#6b7280;margin-bottom:3px'>Payload đã gửi:</div>"
                        f"<pre class='code-block'>{h_payload}</pre></div>"
                        f"<div style='flex:1;min-width:280px'>"
                        f"<div style='font-size:0.72rem;color:#6b7280;margin-bottom:3px'>Phản hồi lỗi:</div>"
                        f"<pre class='code-block' style='color:#fca5a5'>{h_resp}</pre></div>"
                        f"</div></div>"
                    )
                repair_html = (
                    f"<div style='background:rgba(245,158,11,0.1);border-left:4px solid #f59e0b;"
                    f"padding:0.75rem;margin-bottom:0.75rem;border-radius:0 6px 6px 0'>"
                    f"<strong style='color:#f59e0b'>⚠️ {_esc(repair_rsn)}</strong>{hist_items}</div>"
                )

            # Nhãn request tấn công
            attack_badge = ""
            if src.startswith("ATTACKER_"):
                if status_int < 400:
                    attack_badge = (
                        "<span style='background:rgba(239,68,68,0.2);color:#fca5a5;"
                        "border:1px solid #ef4444;padding:2px 8px;border-radius:4px;"
                        "font-size:0.78rem;margin-left:8px;font-weight:700'>⚠️ REQUEST TẤN CÔNG</span>"
                    )

            requests_html += f"""
<div style="background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.06);
     border-left:4px solid {scolor};border-radius:10px;padding:1.25rem;margin-bottom:1rem">
  <div style="display:flex;justify-content:space-between;align-items:center;
       flex-wrap:wrap;margin-bottom:0.75rem;gap:0.5rem">
    <h4 style="color:{scolor};font-family:monospace;font-size:0.9rem;word-break:break-all">
      Lần #{i+1} &nbsp; {_esc(method)} {_esc(path)}
      <span style="background:{scolor}22;color:{scolor};padding:2px 8px;border-radius:4px;
            margin-left:8px">HTTP {status_str}</span>
      {badge}{attack_badge}
    </h4>
  </div>
  {chain_display}
  {repair_html}
  <details>
    <summary style="cursor:pointer;color:#60a5fa;font-size:0.83rem;margin-bottom:0.5rem;user-select:none">
      📋 Headers đã gửi
    </summary>
    <pre class="code-block">{safe_headers}</pre>
  </details>
  <details {"open" if payload else ""}>
    <summary style="cursor:pointer;color:#60a5fa;font-size:0.83rem;margin-bottom:0.5rem;user-select:none">
      📥 Payload gửi lên
    </summary>
    <pre class="code-block">{safe_payload}</pre>
  </details>
  <details open>
    <summary style="cursor:pointer;color:#60a5fa;font-size:0.83rem;margin-bottom:0.5rem;user-select:none">
      📤 Phản hồi từ server
    </summary>
    <pre class="code-block">{safe_resp}</pre>
  </details>
</div>"""

    return f"""
<div id="view_api_{escaped_api}" class="view-section" style="display:none">
  <button onclick="showDashboard()" style="background:none;border:none;cursor:pointer;
    color:#3b82f6;font-size:1rem;font-weight:600;margin-bottom:1.5rem;padding:0">
    ← Quay lại Dashboard
  </button>
  <h2 style="font-size:1.8rem;margin-bottom:0.5rem">
    API: <span style="font-family:'Fira Code',monospace;color:#60a5fa">{escaped_api}</span>
  </h2>
  <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.5rem;flex-wrap:wrap">
    <span style="color:#94a3b8;font-size:0.9rem">Đã gọi {visits} lần</span>
    {status_pills}
  </div>
  <h3 style="font-size:1.1rem;margin-bottom:1rem;border-bottom:1px solid rgba(255,255,255,0.08);padding-bottom:0.5rem">
    Lịch sử Request / Phản hồi
  </h3>
  {requests_html}
</div>"""


# ── Hàm chính tạo báo cáo ────────────────────────────────────────────────────

def generate_html_report(json_file="beam_strategies.json", output_dir="fuzzing_report"):
    if not os.path.exists(json_file):
        print(f"[!] Loi: {json_file} khong ton tai.")
        return

    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "index.html")

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary          = data.get("summary", {})
    total_requests   = summary.get("total_requests", 0)
    server_errors    = summary.get("server_errors_500", 0)
    auth_anomalies   = summary.get("auth_anomalies", 0)
    total_strategies = summary.get("total_strategies_found", 0)
    top_strategies   = data.get("top_strategies", [])
    findings         = data.get("findings", [])
    endpoint_stats   = data.get("endpoint_stats", {})

    bola_count     = sum(
        1 for f in findings
        if "BOLA" in str(f.get("type","")).upper() or "IDOR" in str(f.get("type","")).upper()
    )
    total_findings = len(findings)
    generated_at   = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Các section HTML
    all_apis_html = "".join(
        _build_api_detail(api, stats)
        for api, stats in endpoint_stats.items()
    )

    # Phân nhóm API theo trạng thái
    success_apis, failed_apis, error_500_apis = [], [], []
    for api, stats in endpoint_stats.items():
        sc = stats.get("status_counts", {})
        if any(str(c).startswith("5") for c in sc):
            error_500_apis.append(api)
        elif any(str(c).startswith("2") for c in sc):
            success_apis.append(api)
        else:
            failed_apis.append(api)

    def _badges(api_list, bg):
        if not api_list:
            return "<span style='color:#64748b;font-size:0.85rem'>Không có</span>"
        return " ".join(
            f"<a href='javascript:void(0)' onclick='showApi(\"{_esc(a)}\")' "
            f"style='background:{bg};color:#fff;padding:3px 8px;border-radius:4px;"
            f"font-size:0.78rem;font-family:monospace;text-decoration:none;"
            f"display:inline-block;margin-bottom:4px'>{_esc(a)}</a>"
            for a in api_list
        )

    success_badges   = _badges(success_apis,   "#10b981")
    failed_badges    = _badges(failed_apis,    "#f59e0b")
    error_500_badges = _badges(error_500_apis, "#ef4444")

    # Tóm tắt lỗ hổng — bảng
    vuln_summary_table = _build_vuln_summary_table(findings)

    # Top attack chains
    top_strategies = sorted(top_strategies, key=lambda x: x.get("score", 0), reverse=True)
    strategies_html = ""
    for idx, strat in enumerate(top_strategies):
        rank  = strat.get("rank", idx + 1)
        score = strat.get("score", 0)
        bucket= strat.get("bucket", "?")
        depth = strat.get("depth", len(strat.get("chain", [])))
        chain = strat.get("chain", [])
        state = strat.get("captured_state", {})
        vulns = strat.get("vulnerabilities", [])

        chain_parts = []
        for i, n in enumerate(chain):
            arrow = '<span style="color:#8b5cf6;margin-left:6px">→</span>' if i < len(chain) - 1 else ''
            chain_parts.append(
                f"<div style='display:flex;align-items:center;margin-bottom:0.4rem'>"
                f"<span style='color:#64748b;width:24px;font-size:0.8rem'>{i+1}.</span>"
                f"<a href='javascript:void(0)' onclick='showApi(\"{_esc(n)}\")'  "
                f"style='font-family:monospace;font-size:0.83rem;color:#e2e8f0;text-decoration:none;"
                f"border-bottom:1px dashed #475569'>{_esc(n)}</a>{arrow}</div>"
            )
        chain_html = "".join(chain_parts)

        state_html = ""
        if state:
            safe_state = _esc(json.dumps(state, indent=2, ensure_ascii=False))
            state_html = (
                f"<details style='margin-top:0.75rem'>"
                f"<summary style='cursor:pointer;color:#10b981;font-size:0.82rem;user-select:none'>"
                f"🗃 Trạng thái thu thập được</summary>"
                f"<pre style='font-family:monospace;font-size:0.75rem;color:#94a3b8;"
                f"background:rgba(0,0,0,0.2);padding:0.6rem;border-radius:4px;margin-top:0.4rem;"
                f"white-space:pre-wrap;border-left:2px solid #10b981'>{safe_state}</pre>"
                f"</details>"
            )

        vuln_html = ""
        if vulns:
            vuln_items = ""
            for v in vulns[:5]:
                vtype  = _finding_type_vi(v.get("type", ""))
                vstrat = _strategy_vi(v.get("strategy", ""))
                vapi   = v.get("api", "")
                vstatus= v.get("status", 0)
                vc     = _status_color(int(vstatus) if str(vstatus).isdigit() else 0)
                icon   = _finding_icon(v.get("type", ""))
                strat_span = f'<span style="color:#94a3b8;margin-left:6px">qua {_esc(vstrat)}</span>' if vstrat else ''
                vuln_items += (
                    f"<div style='background:rgba(239,68,68,0.08);border-left:3px solid #ef4444;"
                    f"padding:0.5rem 0.75rem;margin-bottom:0.4rem;border-radius:0 4px 4px 0;"
                    f"font-size:0.82rem'>"
                    f"<span style='color:#fca5a5;font-weight:600'>{icon} {_esc(vtype)}</span>"
                    f"{strat_span}"
                    f"<span style='float:right;color:{vc}'>HTTP {vstatus}</span><br>"
                    f"<span style='font-family:monospace;color:#94a3b8;font-size:0.78rem'>{_esc(vapi)}</span>"
                    f"</div>"
                )
            vuln_html = (
                f"<div style='margin-top:0.75rem;border-top:1px solid rgba(255,255,255,0.06);padding-top:0.75rem'>"
                f"<div style='color:#ef4444;font-size:0.82rem;font-weight:600;margin-bottom:0.4rem'>"
                f"⚠️ Lỗ hổng phát hiện được</div>{vuln_items}</div>"
            )

        strategies_html += f"""
<div class="strategy-card">
  <div class="card-header">
    <span class="rank-badge">#{rank}</span>
    <span class="score-badge">⭐ {score} điểm</span>
  </div>
  <div style="font-size:0.75rem;color:#64748b;margin-bottom:0.75rem">
    Độ sâu: {depth} &nbsp;|&nbsp; Nhóm: {_esc(bucket)}
  </div>
  <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:0.4rem">Chuỗi tấn công:</div>
  <div style="background:rgba(0,0,0,0.25);border-radius:8px;padding:0.75rem;margin-bottom:0.5rem">
    {chain_html}
  </div>
  {state_html}
  {vuln_html}
</div>"""

    if not strategies_html:
        strategies_html = "<p style='color:#64748b;text-align:center'>Chưa có chiến lược nào.</p>"

    findings_section = _build_findings_section(findings)

    # ── Lắp ráp HTML ─────────────────────────────────────────────────────────
    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OPG — Báo cáo kiểm thử bảo mật API</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=Fira+Code:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg:      #0f172a;
      --surface: rgba(30,41,59,0.75);
      --text:    #f8fafc;
      --muted:   #94a3b8;
      --blue:    #3b82f6;
      --purple:  #8b5cf6;
      --green:   #10b981;
      --red:     #ef4444;
      --orange:  #f59e0b;
    }}
    * {{ margin:0;padding:0;box-sizing:border-box }}
    body {{
      font-family:'Inter',sans-serif;
      background-color:var(--bg);
      background-image:
        radial-gradient(at 0% 0%,rgba(59,130,246,.12) 0,transparent 50%),
        radial-gradient(at 100% 100%,rgba(139,92,246,.12) 0,transparent 50%);
      background-attachment:fixed;
      color:var(--text);min-height:100vh;padding:2rem;line-height:1.6
    }}
    .container {{ max-width:1280px;margin:0 auto }}
    header {{ text-align:center;margin-bottom:2.5rem }}
    h1 {{
      font-size:2.8rem;font-weight:800;letter-spacing:-1px;
      background:linear-gradient(135deg,var(--blue),var(--purple));
      -webkit-background-clip:text;-webkit-text-fill-color:transparent
    }}
    .subtitle {{ color:var(--muted);font-size:1rem;margin-top:0.25rem }}
    .meta {{ color:#475569;font-size:0.8rem;margin-top:0.25rem }}

    .stats-row {{ display:flex;flex-wrap:wrap;gap:1rem;justify-content:center;margin-bottom:2.5rem }}
    .stat-card {{
      background:var(--surface);backdrop-filter:blur(12px);
      border:1px solid rgba(255,255,255,.08);border-radius:14px;
      padding:1.25rem 2rem;text-align:center;flex:1;min-width:140px;max-width:180px;
      transition:transform .25s
    }}
    .stat-card:hover {{ transform:translateY(-4px) }}
    .stat-num   {{ font-size:2.2rem;font-weight:800 }}
    .stat-label {{ color:var(--muted);font-size:0.75rem;text-transform:uppercase;letter-spacing:.8px;margin-top:2px }}

    .tabs {{ display:flex;border-bottom:2px solid rgba(255,255,255,.08);margin-bottom:2rem;gap:0.25rem;flex-wrap:wrap }}
    .tab-btn {{
      padding:0.6rem 1.2rem;border:none;background:none;cursor:pointer;
      color:var(--muted);font-size:0.88rem;font-family:'Inter',sans-serif;
      border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .2s;
      border-radius:6px 6px 0 0
    }}
    .tab-btn.active {{ color:var(--blue);border-bottom-color:var(--blue);background:rgba(59,130,246,.08) }}
    .tab-btn:hover:not(.active) {{ color:var(--text);background:rgba(255,255,255,.05) }}
    .tab-panel {{ display:none }}
    .tab-panel.active {{ display:block }}

    .strategies-grid {{ display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1.25rem }}
    .strategy-card {{
      background:var(--surface);backdrop-filter:blur(12px);
      border:1px solid rgba(255,255,255,.06);border-radius:14px;
      padding:1.25rem;transition:all .25s;position:relative;overflow:hidden
    }}
    .strategy-card::before {{
      content:'';position:absolute;top:0;left:0;width:3px;height:100%;
      background:var(--blue);transition:background .25s
    }}
    .strategy-card:hover {{ transform:translateY(-4px);border-color:rgba(255,255,255,.12) }}
    .strategy-card:hover::before {{ background:var(--purple) }}
    .card-header {{ display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem }}
    .rank-badge {{
      background:rgba(59,130,246,.2);color:#60a5fa;
      padding:3px 10px;border-radius:999px;font-size:0.8rem;font-weight:600
    }}
    .score-badge {{ color:var(--orange);font-weight:700;font-size:0.88rem }}

    .code-block {{
      background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.08);
      border-radius:6px;padding:0.75rem;overflow-x:auto;
      font-family:'Fira Code',monospace;font-size:0.82rem;color:#e2e8f0;
      white-space:pre-wrap;word-break:break-all;margin-top:0.4rem
    }}
    .section-title {{
      font-size:1.5rem;font-weight:700;margin-bottom:1.25rem;
      border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:0.5rem
    }}

    @keyframes fadeIn {{ from{{opacity:0;transform:translateY(10px)}} to{{opacity:1;transform:translateY(0)}} }}
    .strategy-card {{ animation:fadeIn .4s ease-out both }}
  </style>
</head>
<body>
<div class="container">

  <!-- DASHBOARD -->
  <div id="view_dashboard" class="view-section">
    <header>
      <h1>OPG — Báo cáo Bảo mật API</h1>
      <p class="subtitle">Hệ thống kiểm thử BOLA/IDOR đa tác nhân — Tìm kiếm chùm tia có trạng thái</p>
      <p class="meta">Thời điểm tạo: {generated_at}</p>
    </header>

    <!-- Thống kê tổng quan -->
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-num" style="color:var(--blue)">{total_requests}</div>
        <div class="stat-label">Tổng số request</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:var(--red)">{bola_count}</div>
        <div class="stat-label">Lỗ hổng BOLA/IDOR</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:var(--orange)">{server_errors}</div>
        <div class="stat-label">Crash / Lỗi 500</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:var(--purple)">{auth_anomalies}</div>
        <div class="stat-label">Bất thường xác thực</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:var(--green)">{total_findings}</div>
        <div class="stat-label">Tổng phát hiện</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:var(--muted)">{total_strategies}</div>
        <div class="stat-label">Chuỗi tấn công</div>
      </div>
    </div>

    <!-- Tabs chính -->
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('findings', this)">
        🔓 Lỗ hổng phát hiện ({total_findings})
      </button>
      <button class="tab-btn" onclick="switchTab('api_status', this)">
        📊 Phạm vi kiểm thử API
      </button>
      <button class="tab-btn" onclick="switchTab('strategies', this)">
        ⚔️ Chuỗi tấn công tốt nhất
      </button>
    </div>

    <!-- Tab: Lỗ hổng -->
    <div id="tab_findings" class="tab-panel active">
      <h2 class="section-title">Lỗ hổng bảo mật phát hiện được</h2>
      {vuln_summary_table}
      <h3 style="font-size:1.1rem;color:#94a3b8;margin-bottom:1rem;margin-top:1.5rem">
        Chi tiết theo loại
      </h3>
      {findings_section}
    </div>

    <!-- Tab: Phạm vi API -->
    <div id="tab_api_status" class="tab-panel">
      <h2 class="section-title">Phạm vi kiểm thử API</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.25rem">
        <div style="background:rgba(16,185,129,.08);border:1px solid var(--green);border-radius:12px;padding:1.25rem">
          <h3 style="color:var(--green);margin-bottom:0.75rem;display:flex;justify-content:space-between">
            <span>✅ Thành công (2xx)</span><span>{len(success_apis)} API</span>
          </h3>
          <div style="display:flex;flex-wrap:wrap;gap:0.4rem">{success_badges}</div>
        </div>
        <div style="background:rgba(245,158,11,.08);border:1px solid var(--orange);border-radius:12px;padding:1.25rem">
          <h3 style="color:var(--orange);margin-bottom:0.75rem;display:flex;justify-content:space-between">
            <span>⚠️ Thất bại (4xx)</span><span>{len(failed_apis)} API</span>
          </h3>
          <div style="display:flex;flex-wrap:wrap;gap:0.4rem">{failed_badges}</div>
        </div>
        <div style="background:rgba(239,68,68,.08);border:1px solid var(--red);border-radius:12px;padding:1.25rem">
          <h3 style="color:var(--red);margin-bottom:0.75rem;display:flex;justify-content:space-between">
            <span>💥 Lỗi server (5xx)</span><span>{len(error_500_apis)} API</span>
          </h3>
          <div style="display:flex;flex-wrap:wrap;gap:0.4rem">{error_500_badges}</div>
        </div>
      </div>
    </div>

    <!-- Tab: Chuỗi tấn công -->
    <div id="tab_strategies" class="tab-panel">
      <h2 class="section-title">Chuỗi tấn công tốt nhất</h2>
      <div class="strategies-grid">{strategies_html}</div>
    </div>

  </div><!-- END DASHBOARD -->

  <!-- Chi tiết từng API -->
  {all_apis_html}

</div>

<script>
  function switchTab(name, btn) {{
    document.querySelectorAll('.tab-panel').forEach(function(p) {{ p.classList.remove('active'); }});
    document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
    document.getElementById('tab_' + name).classList.add('active');
    if (btn) btn.classList.add('active');
  }}
  function showDashboard() {{
    document.querySelectorAll('.view-section').forEach(function(el) {{ el.style.display = 'none'; }});
    document.getElementById('view_dashboard').style.display = 'block';
    window.scrollTo(0, 0);
  }}
  function showApi(apiId) {{
    document.querySelectorAll('.view-section').forEach(function(el) {{ el.style.display = 'none'; }});
    var el = document.getElementById('view_api_' + apiId);
    if (el) {{ el.style.display = 'block'; window.scrollTo(0, 0); }}
    else {{ alert('Khong co du lieu cho: ' + apiId); showDashboard(); }}
  }}
</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[OK] Bao cao da duoc luu tai: {output_file}")
    print(f"     BOLA/IDOR: {bola_count}  |  Crash: {server_errors}  |  Tong phat hien: {total_findings}")


if __name__ == "__main__":
    generate_html_report()
