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
from urllib.parse import urlsplit
from response_outcome import evaluate_response
from knowledge_memory import sanitize_sensitive


# ── Hàm hỗ trợ ───────────────────────────────────────────────────────────────

def _esc(s) -> str:
    return html.escape(str(s))


def _status_color(status: int) -> str:
    if status >= 500: return "#ef4444"
    if status >= 400: return "#f59e0b"
    if status >= 200: return "#10b981"
    return "#94a3b8"


def _format_duration(milliseconds) -> str:
    """Render a duration compactly while accepting reports without timing data."""
    if not isinstance(milliseconds, (int, float)) or milliseconds < 0:
        return "Không có dữ liệu"
    if milliseconds < 1000:
        return f"{milliseconds:.0f} ms"
    seconds = milliseconds / 1000
    if seconds < 60:
        return f"{seconds:.2f} giây"
    minutes, remaining = divmod(seconds, 60)
    return f"{int(minutes)} phút {remaining:.1f} giây"


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


_ATTACK_LABELS = {
    "id_substitution": "Thay thế định danh (BOLA/IDOR)",
    "param_pollution": "Chèn / làm nhiễu tham số",
    "reference_forge": "Giả mạo tham chiếu tài nguyên",
}

_SENSITIVE_KEYS = (
    "authorization", "token", "secret", "password", "passwd", "cookie",
    "api_key", "apikey", "session", "credential",
)


def _redact_sensitive(value, key: str = ""):
    """Redact with the same policy used before JSON persistence."""
    return sanitize_sensitive(value, key)


def _flatten_values(value, prefix: str) -> dict:
    """Trải phẳng JSON để so sánh request hợp lệ và request tấn công."""
    if not isinstance(value, dict):
        return {prefix: value}
    flattened = {}
    for key, child in value.items():
        child_path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, dict):
            flattened.update(_flatten_values(child, child_path))
        else:
            flattened[child_path] = child
    return flattened


def _group_apis_by_outcome(endpoint_stats: dict) -> tuple[list, list]:
    """Ưu tiên 2xx: từng lỗi 5xx vẫn là thành công nếu có ít nhất một 2xx."""
    success_apis = []
    failed_apis = []
    for api, stats in endpoint_stats.items():
        status_counts = stats.get("status_counts", {})
        requests = stats.get("all_requests", [])
        baseline_requests = [
            request for request in requests
            if not _is_security_probe(request)
        ]
        measured_requests = baseline_requests or requests
        if measured_requests:
            request_outcomes = []
            for request in measured_requests:
                if "successful" in request:
                    request_outcomes.append(request.get("successful") is True)
                else:
                    request_outcomes.append(evaluate_response(
                        request.get("status", 0),
                        response_text=request.get("response_text", ""),
                    ).successful)
            has_success = any(request_outcomes)
        else:
            has_success = any(str(status).startswith("2") for status in status_counts)
        target = (
            success_apis
            if has_success
            else failed_apis
        )
        target.append(api)
    return success_apis, failed_apis


def _is_security_probe(request: dict) -> bool:
    source = str(request.get("payload_source", "")).upper()
    return source.startswith("ATTACKER_") or source == "LOCAL_MUTATOR"


def _request_succeeded(request: dict) -> bool:
    if "successful" in request:
        return request.get("successful") is True
    return evaluate_response(
        request.get("status", 0),
        response_text=request.get("response_text", ""),
    ).successful


def _build_attack_explanation(method: str, metadata: dict, sent_query: dict,
                              sent_cookies: dict, sent_body: dict) -> str:
    if not metadata:
        return ""

    strategy = str(metadata.get("strategy", "unknown"))
    technique = str(metadata.get("technique", strategy)).replace("_", " ")
    strategy_label = _ATTACK_LABELS.get(strategy, strategy.replace("_", " ").title())
    description = metadata.get("description") or "Biến đổi request hợp lệ để kiểm tra kiểm soát truy cập."
    owner = metadata.get("owner_actor_id", "không xác định")
    attacker = metadata.get("attacker_actor_id", "không xác định")
    baseline = metadata.get("baseline", {}) if isinstance(metadata.get("baseline"), dict) else {}
    attack = metadata.get("attack", {}) if isinstance(metadata.get("attack"), dict) else {}
    baseline_path = baseline.get("path", "")
    attack_path = attack.get("path", "")

    before = {}
    before.update(_flatten_values(baseline.get("body", {}), "body"))
    before.update(_flatten_values(baseline.get("query", {}), "query"))
    after = {}
    after.update(_flatten_values(attack.get("body", sent_body), "body"))
    after.update(_flatten_values(attack.get("query", sent_query), "query"))

    changes = []
    if baseline_path and baseline_path != attack_path:
        changes.append(("path", baseline_path, attack_path))
    for field in sorted(set(before) | set(after)):
        old_value = before.get(field, "<không có>")
        new_value = after.get(field, "<đã xóa>")
        if old_value != new_value:
            changes.append((field, old_value, new_value))

    if changes:
        change_rows = "".join(
            "<tr>"
            f"<td style='padding:6px;color:#fbbf24;font-family:monospace'>{_esc(field)}</td>"
            f"<td style='padding:6px;color:#94a3b8;font-family:monospace;word-break:break-all'>{_esc(json.dumps(_redact_sensitive(old, field), ensure_ascii=False))}</td>"
            f"<td style='padding:6px;color:#fca5a5;font-family:monospace;word-break:break-all'>{_esc(json.dumps(_redact_sensitive(new, field), ensure_ascii=False))}</td>"
            "</tr>"
            for field, old, new in changes
        )
    else:
        change_rows = (
            "<tr><td colspan='3' style='padding:6px;color:#94a3b8'>"
            "Không phát hiện khác biệt cấu trúc; kỹ thuật có thể nằm ở danh tính/phiên xác thực.</td></tr>"
        )

    safe_query = _esc(json.dumps(_redact_sensitive(sent_query), indent=2, ensure_ascii=False))
    safe_cookies = _esc(json.dumps(_redact_sensitive(sent_cookies), indent=2, ensure_ascii=False))
    safe_body = _esc(json.dumps(_redact_sensitive(sent_body), indent=2, ensure_ascii=False))

    transport_blocks = []
    if sent_query:
        transport_blocks.append(
            f"<div><div style='color:#94a3b8;font-size:0.78rem;margin-bottom:3px'>Query thực gửi</div><pre class='code-block'>{safe_query}</pre></div>"
        )
    if sent_body:
        transport_blocks.append(
            f"<div><div style='color:#94a3b8;font-size:0.78rem;margin-bottom:3px'>JSON / body thực gửi</div><pre class='code-block'>{safe_body}</pre></div>"
        )
    if sent_cookies:
        transport_blocks.append(
            f"<div><div style='color:#94a3b8;font-size:0.78rem;margin-bottom:3px'>Cookie thực gửi (đã che)</div><pre class='code-block'>{safe_cookies}</pre></div>"
        )
    if not transport_blocks:
        transport_blocks.append(
            "<div style='color:#94a3b8'>Request không có body/query; biến đổi nằm ở URL hoặc danh tính gửi request.</div>"
        )

    return f"""
<section style="background:rgba(127,29,29,0.18);border:1px solid rgba(248,113,113,0.45);
         border-radius:8px;padding:1rem;margin-bottom:0.9rem">
  <div style="color:#fca5a5;font-weight:800;font-size:1rem;margin-bottom:0.65rem">🎯 Cách tấn công</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:0.5rem;margin-bottom:0.75rem">
    <div><span style="color:#94a3b8">Chiến lược:</span> <strong>{_esc(strategy_label)}</strong></div>
    <div><span style="color:#94a3b8">Kỹ thuật:</span> <code>{_esc(technique)}</code></div>
    <div><span style="color:#94a3b8">Luồng actor:</span> <code>{_esc(owner)} → {_esc(attacker)}</code></div>
  </div>
  <div style="margin-bottom:0.75rem;color:#e2e8f0"><strong>Mục đích:</strong> {_esc(description)}</div>
  <div style="margin-bottom:0.75rem">
    <div style="color:#94a3b8;font-size:0.78rem;margin-bottom:3px">Request tấn công thực tế</div>
    <code style="color:#fbbf24;word-break:break-all">{_esc(method.upper())} {_esc(attack_path)}</code>
  </div>
  <div style="color:#e2e8f0;font-weight:700;margin-bottom:0.35rem">Thay đổi so với request hợp lệ</div>
  <div style="overflow-x:auto;margin-bottom:0.75rem">
    <table style="width:100%;border-collapse:collapse;font-size:0.8rem">
      <thead><tr style="text-align:left;color:#94a3b8;border-bottom:1px solid rgba(255,255,255,0.12)">
        <th style="padding:6px">Vị trí</th><th style="padding:6px">Trước</th><th style="padding:6px">Sau</th>
      </tr></thead><tbody>{change_rows}</tbody>
    </table>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:0.75rem">
    {''.join(transport_blocks)}
  </div>
</section>"""


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


def _aggregate_findings(findings: list) -> list:
    """Group report rows by API + method + type, retaining every raw variant."""
    grouped = {}
    for raw in findings or []:
        finding = dict(raw)
        method = str(finding.get("method") or "GET").strip().upper()
        finding_type = str(
            finding.get("finding_type") or finding.get("type") or "unknown"
        ).strip()

        # `api` is the stable OpenAPI operation identifier in this output. It
        # prevents concrete attack URLs (/users/1, /users/2) being counted as
        # different APIs. Fall back to the route/path for older report files.
        endpoint = str(
            finding.get("endpoint") or finding.get("api")
            or finding.get("api_id") or finding.get("path") or "/"
        ).strip()
        if endpoint.startswith(("http://", "https://")):
            endpoint = urlsplit(endpoint).path
        endpoint = endpoint.split("?", 1)[0] or "/"

        key = (endpoint, method, finding_type.casefold())
        aggregate = grouped.get(key)
        if aggregate is None:
            aggregate = dict(finding)
            aggregate["endpoint"] = endpoint
            aggregate["method"] = method
            aggregate["finding_type"] = finding_type
            aggregate["variants"] = []
            grouped[key] = aggregate

        aggregate["variants"].append(finding)
        aggregate["variant_count"] = len(aggregate["variants"])

    return list(grouped.values())


def _build_auth_bootstrap_section(events: list) -> str:
    """Render authentication setup evidence without treating it as a finding."""
    if not events:
        return (
            "<div style='background:rgba(148,163,184,.08);border:1px solid #475569;"
            "border-radius:10px;padding:1.25rem;color:#94a3b8'>"
            "Không có bootstrap tự động hoặc bootstrap đã được tắt.</div>"
        )

    cards = []
    for event in events:
        successful = event.get("successful") is True
        color = "#10b981" if successful else "#ef4444"
        label = "THÀNH CÔNG" if successful else "THẤT BẠI"
        status = event.get("status", 0)
        performed_by = event.get("performed_by") or event.get("actor_id", "")
        requested_role = event.get("requested_role")
        effective_role = event.get("effective_role")
        role_mismatch = (
            requested_role not in (None, "")
            and effective_role not in (None, "")
            and str(requested_role).casefold() != str(effective_role).casefold()
        )
        role_note = ""
        if role_mismatch:
            role_note = (
                "<div style='margin-top:.6rem;background:rgba(245,158,11,.1);"
                "border-left:3px solid #f59e0b;padding:.55rem .7rem;color:#fbbf24'>"
                "Role server trả về khác role đã yêu cầu; report dùng role hiệu lực từ server."
                "</div>"
            )
        transports = event.get("auth_transports", []) or []
        transport_text = ", ".join(
            f"{item.get('kind')}:{item.get('name')}"
            for item in transports if isinstance(item, dict)
        ) or "không ghi nhận"
        request_json = _esc(json.dumps(
            _redact_sensitive(event.get("request_payload", {})),
            indent=2,
            ensure_ascii=False,
        ))
        response_json = _esc(json.dumps(
            _redact_sensitive(event.get("response_body")),
            indent=2,
            ensure_ascii=False,
        ))
        cards.append(f"""
<div style="background:rgba(30,41,59,.8);border:1px solid rgba(255,255,255,.08);
     border-left:4px solid {color};border-radius:10px;padding:1.1rem;margin-bottom:1rem">
  <div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap">
    <div>
      <strong style="color:{color}">{_esc(str(event.get('stage', 'auth')).upper())} · {label}</strong>
      <div style="font-family:'Fira Code',monospace;color:#cbd5e1;margin-top:.35rem">
        {_esc(event.get('method', 'POST'))} {_esc(event.get('path', ''))}
      </div>
    </div>
    <div style="text-align:right;color:#94a3b8;font-size:.84rem">
      actor: <strong style="color:#e2e8f0">{_esc(event.get('actor_id', ''))}</strong><br>
      thực thi bởi: <strong style="color:#e2e8f0">{_esc(performed_by)}</strong><br>
      HTTP {_esc(status)}
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.6rem;
       margin-top:.8rem;color:#94a3b8;font-size:.84rem">
    <div>Role yêu cầu: <strong style="color:#cbd5e1">{_esc(requested_role or 'không khai báo')}</strong></div>
    <div>Role hiệu lực: <strong style="color:#cbd5e1">{_esc(effective_role or 'không xác định')}</strong></div>
    <div>Auth transport: <strong style="color:#cbd5e1">{_esc(transport_text)}</strong></div>
  </div>
  {role_note}
  <details style="margin-top:.75rem">
    <summary style="cursor:pointer;color:#60a5fa;font-size:.84rem">Request/response bootstrap đã che bí mật</summary>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:.75rem;margin-top:.6rem">
      <div><div style="color:#94a3b8;font-size:.78rem">REQUEST</div><pre class="code-block">{request_json}</pre></div>
      <div><div style="color:#94a3b8;font-size:.78rem">RESPONSE</div><pre class="code-block">{response_json}</pre></div>
    </div>
  </details>
</div>""")
    return "".join(cards)


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
    <a href="#" class="api-link" data-api-id="{_esc(api)}"
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
        variants   = f.get("variants", [f])
        variant_count = len(variants)

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

        variant_badge = (
            f"<span style='background:rgba(59,130,246,0.16);color:#93c5fd;"
            f"padding:2px 8px;border-radius:4px;font-size:0.78rem;margin-left:8px'>"
            f"{variant_count} biến thể</span>"
        )
        variant_items = "".join(
            f"<li style='margin-bottom:5px;color:#cbd5e1'>"
            f"<strong>{_esc(v.get('strategy', 'variant'))}</strong> — "
            f"HTTP {_esc(v.get('status', 'N/A'))}: "
            f"{_esc(v.get('description') or '; '.join(map(str, v.get('evidence', v.get('details', []))[:2])) or 'Không có mô tả')}"
            f"</li>"
            for v in variants
        )
        variants_html = (
            f"<details style='margin-top:0.75rem'>"
            f"<summary style='cursor:pointer;color:#93c5fd;font-size:0.85rem'>"
            f"Các biến thể/evidence ({variant_count})</summary>"
            f"<ol style='margin-top:0.5rem;padding-left:1.3rem;font-size:0.82rem'>{variant_items}</ol>"
            f"</details>"
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
      {variant_badge}
    </div>
    <span style="color:{_status_color(int(status) if str(status).isdigit() else 0)};
          font-family:monospace;font-size:0.9rem;font-weight:700">HTTP {status}</span>
  </div>

  <div style="font-family:'Fira Code',monospace;font-size:0.88rem;color:#e2e8f0;margin-bottom:0.5rem">
    <span style="color:#64748b">{_esc(method)}</span>
    &nbsp;<a href="#" class="api-link" data-api-id="{_esc(api)}"
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
  {variants_html}
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
    baseline_requests = [req for req in all_requests if not _is_security_probe(req)]
    security_probes = [req for req in all_requests if _is_security_probe(req)]
    baseline_successes = sum(1 for req in baseline_requests if _request_succeeded(req))
    baseline_rate = (
        round(100 * baseline_successes / len(baseline_requests), 1)
        if baseline_requests else 0
    )

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
            query      = req.get("sent_query", {})
            cookies    = req.get("sent_cookies", {})
            sent_files = req.get("sent_files", {})
            attack_meta= req.get("attack_metadata", {})
            successful = req.get("successful")
            semantic_failure = req.get("semantic_failure", False)
            outcome_reason = req.get("outcome_reason", "")
            auth_recovery = req.get("auth_recovery", {})
            chain      = req.get("chain", [])
            repair_rsn = req.get("repair_reason", "")
            repair_hist= req.get("repair_history", [])
            elapsed_label = _format_duration(req.get("elapsed_ms"))
            timing_badge = ""
            if req.get("elapsed_ms") is not None:
                timing_badge = (
                    "<span style='background:rgba(59,130,246,0.15);color:#93c5fd;"
                    "border:1px solid #3b82f6;padding:2px 8px;border-radius:4px;"
                    f"font-size:0.78rem;margin-left:8px'>⏱ {_esc(elapsed_label)}</span>"
                )

            if successful is None:
                legacy_outcome = evaluate_response(
                    status_int,
                    response_text=resp_text,
                )
                successful = legacy_outcome.successful
                semantic_failure = legacy_outcome.semantic_failure
                outcome_reason = legacy_outcome.reason

            scolor = "#f59e0b" if semantic_failure else _status_color(status_int)
            badge  = _source_badge(src)

            outcome_badge = ""
            if semantic_failure or successful is False and 200 <= status_int < 300:
                outcome_badge = (
                    "<span style='background:rgba(245,158,11,0.18);color:#fbbf24;"
                    "border:1px solid #f59e0b;padding:2px 8px;border-radius:4px;"
                    "font-size:0.78rem;margin-left:8px;font-weight:700' "
                    f"title='{_esc(outcome_reason)}'>NGHIỆP VỤ THẤT BẠI</span>"
                )

            auth_recovery_html = ""
            if auth_recovery.get("attempted"):
                recovered = bool(auth_recovery.get("recovered"))
                recovery_color = "#10b981" if recovered else "#ef4444"
                recovery_label = "Đã khôi phục auth context" if recovered else "Khôi phục auth context thất bại"
                events = auth_recovery.get("events", [])
                reasons = "; ".join(
                    str(event.get("reason", "")) for event in events if event.get("reason")
                )
                recovery_reason = str(auth_recovery.get("reason", ""))
                details = "; ".join(part for part in (reasons, recovery_reason) if part)
                auth_recovery_html = (
                    f"<div style='background:{recovery_color}18;border-left:4px solid {recovery_color};"
                    f"padding:0.75rem;margin-bottom:0.75rem;border-radius:0 6px 6px 0'>"
                    f"<strong style='color:{recovery_color}'>🔄 {_esc(recovery_label)}</strong>"
                    f"<div style='color:#94a3b8;font-size:0.8rem;margin-top:4px'>"
                    f"{_esc(details or 'Token/session đã được làm mới trước khi retry request.')}</div></div>"
                )
                outcome_badge += (
                    "<span style='background:rgba(139,92,246,0.18);color:#c4b5fd;"
                    "border:1px solid #8b5cf6;padding:2px 8px;border-radius:4px;"
                    "font-size:0.78rem;margin-left:8px;font-weight:700'>AUTH-STATE RECOVERY</span>"
                )

            # Báo cáo cũ chưa có attack_metadata vẫn hiển thị được request
            # thực gửi. Báo cáo mới có thêm baseline để dựng bảng before/after.
            if src.startswith("ATTACKER_") and not attack_meta:
                legacy_strategy = src[len("ATTACKER_"):].lower()
                attack_meta = {
                    "strategy": legacy_strategy,
                    "technique": legacy_strategy,
                    "description": "Request biến đổi dùng để kiểm tra BOLA / broken access control.",
                    "attacker_actor_id": req.get("actor_id") or "không xác định",
                    "attack": {"path": path, "body": payload, "query": query},
                }

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
            safe_headers = _esc(json.dumps(
                _redact_sensitive(headers_display), indent=2, ensure_ascii=False
            ))

            safe_payload = _esc(json.dumps(
                _redact_sensitive(payload), indent=2, ensure_ascii=False
            ))
            safe_files = _esc(json.dumps(
                _redact_sensitive(sent_files), indent=2, ensure_ascii=False
            ))
            upload_html = ""
            if sent_files:
                upload_html = f"""<details open>
    <summary style="cursor:pointer;color:#60a5fa;font-size:0.83rem;margin-bottom:0.5rem;user-select:none">
      📎 File upload ({len(sent_files)})
    </summary>
    <pre class="code-block">{safe_files}</pre>
  </details>"""
            try:
                safe_resp = _esc(json.dumps(
                    _redact_sensitive(json.loads(resp_text)),
                    indent=2,
                    ensure_ascii=False,
                ))
            except Exception:
                safe_resp = _esc(str(_redact_sensitive(resp_text)))

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
                    h_payload = _esc(json.dumps(
                        _redact_sensitive(h.get("payload", {})),
                        indent=2,
                        ensure_ascii=False,
                    ))
                    try:
                        h_resp = _esc(json.dumps(
                            _redact_sensitive(json.loads(str(h.get("response", "")))),
                            indent=2,
                            ensure_ascii=False,
                        ))
                    except Exception:
                        h_resp = _esc(str(_redact_sensitive(h.get("response", ""))))
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
                attack_badge = (
                    "<span style='background:rgba(239,68,68,0.2);color:#fca5a5;"
                    "border:1px solid #ef4444;padding:2px 8px;border-radius:4px;"
                    "font-size:0.78rem;margin-left:8px;font-weight:700'>⚠️ REQUEST TẤN CÔNG</span>"
                )

            attack_explanation = _build_attack_explanation(
                method=method,
                metadata=attack_meta,
                sent_query=query,
                sent_cookies=cookies,
                sent_body=payload,
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
      {badge}{attack_badge}{outcome_badge}{timing_badge}
    </h4>
  </div>
  {attack_explanation}
  {auth_recovery_html}
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
  {upload_html}
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
  <div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:1.25rem">
    <span style="background:rgba(16,185,129,.1);border:1px solid #10b981;color:#6ee7b7;
          padding:5px 10px;border-radius:6px;font-size:0.82rem">
      Valid workflow: {baseline_successes}/{len(baseline_requests)} ({baseline_rate}%)
    </span>
    <span style="background:rgba(139,92,246,.1);border:1px solid #8b5cf6;color:#c4b5fd;
          padding:5px 10px;border-radius:6px;font-size:0.82rem">
      Security probes (không tính vào tỷ lệ): {len(security_probes)}
    </span>
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
    run_elapsed_label = _format_duration(summary.get("run_elapsed_ms"))
    average_http_elapsed_label = _format_duration(summary.get("average_http_elapsed_ms"))
    run_started_at = summary.get("run_started_at", "Không có dữ liệu")
    run_finished_at = summary.get("run_finished_at", "Không có dữ liệu")
    total_strategies = summary.get("total_strategies_found", 0)
    top_strategies   = data.get("top_strategies", [])
    raw_findings     = data.get("findings", [])
    findings         = _aggregate_findings(raw_findings)
    endpoint_stats   = data.get("endpoint_stats", {})
    pipeline_summary = data.get("pipeline_summary", {})
    auth_bootstrap   = data.get("auth_bootstrap", [])

    bola_count     = sum(
        1 for f in findings
        if "BOLA" in str(f.get("type","")).upper() or "IDOR" in str(f.get("type","")).upper()
    )
    server_errors = sum(
        1 for f in findings
        if "CRASH" in str(f.get("type", "")).upper()
        or "500" in str(f.get("type", "")).upper()
    )
    auth_anomalies = sum(
        1 for f in findings
        if str(f.get("type", "")).strip().casefold() == "auth anomaly".casefold()
    )
    total_findings = len(findings)
    generated_at   = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    phase0 = pipeline_summary.get("phase_0", {})
    phase1 = pipeline_summary.get("phase_1", {})
    phase2 = pipeline_summary.get("phase_2", {})
    pipeline_html = ""
    if pipeline_summary:
        phase2_state = (
            f"Đã kiểm thử {phase2.get('tested_endpoints', 0)} endpoint"
            if phase2.get("enabled") and phase2.get("completed")
            else "Đã tắt" if not phase2.get("enabled") else "Chưa hoàn tất"
        )
        pipeline_html = f"""
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:1.5rem">
      <div style="background:rgba(59,130,246,.08);border:1px solid #3b82f6;border-radius:10px;padding:1rem">
        <div style="color:#93c5fd;font-weight:700">PHASE 0 — Authentication bootstrap</div>
        <div style="color:#cbd5e1;margin-top:5px">{_esc(phase0.get('events', len(auth_bootstrap)))} sự kiện · {'Hoàn tất' if phase0.get('completed', True) else 'Thất bại'}</div>
      </div>
      <div style="background:rgba(16,185,129,.08);border:1px solid #10b981;border-radius:10px;padding:1rem">
        <div style="color:#6ee7b7;font-weight:700">PHASE 1 — Valid workflow</div>
        <div style="color:#cbd5e1;margin-top:5px">Hoàn tất · {_esc(phase1.get('valid_actor_endpoint_baselines', 0))} baseline hợp lệ</div>
      </div>
      <div style="background:rgba(139,92,246,.08);border:1px solid #8b5cf6;border-radius:10px;padding:1rem">
        <div style="color:#c4b5fd;font-weight:700">PHASE 2 — Security validation</div>
        <div style="color:#cbd5e1;margin-top:5px">{_esc(phase2_state)}</div>
      </div>
    </div>"""

    # Các section HTML
    all_apis_html = "".join(
        _build_api_detail(api, stats)
        for api, stats in endpoint_stats.items()
    )

    # Phân nhóm độc quyền theo kết quả cuối: có bất kỳ 2xx => thành công;
    # không có 2xx => thất bại, kể cả endpoint từng/trực tiếp trả 5xx.
    success_apis, failed_apis = _group_apis_by_outcome(endpoint_stats)

    def _badges(api_list, bg):
        if not api_list:
            return "<span style='color:#64748b;font-size:0.85rem'>Không có</span>"
        return " ".join(
            f"<a href='#' class='api-link' data-api-id='{_esc(a)}' "
            f"style='background:{bg};color:#fff;padding:3px 8px;border-radius:4px;"
            f"font-size:0.78rem;font-family:monospace;text-decoration:none;"
            f"display:inline-block;margin-bottom:4px'>{_esc(a)}</a>"
            for a in api_list
        )

    success_badges   = _badges(success_apis,   "#10b981")
    failed_badges    = _badges(failed_apis,    "#f59e0b")

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
                f"<a href='#' class='api-link' data-api-id='{_esc(n)}'  "
                f"style='font-family:monospace;font-size:0.83rem;color:#e2e8f0;text-decoration:none;"
                f"border-bottom:1px dashed #475569'>{_esc(n)}</a>{arrow}</div>"
            )
        chain_html = "".join(chain_parts)

        state_html = ""
        if state:
            safe_state = _esc(json.dumps(
                _redact_sensitive(state), indent=2, ensure_ascii=False
            ))
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
    auth_bootstrap_section = _build_auth_bootstrap_section(auth_bootstrap)

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
      <p class="meta">Bắt đầu chạy: {_esc(run_started_at)} · Kết thúc pipeline: {_esc(run_finished_at)}</p>
    </header>

    {pipeline_html}

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
      <div class="stat-card">
        <div class="stat-num" style="color:var(--blue);font-size:1.35rem">{run_elapsed_label}</div>
        <div class="stat-label">Tổng thời gian chạy</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:var(--green);font-size:1.35rem">{average_http_elapsed_label}</div>
        <div class="stat-label">HTTP trung bình</div>
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
      <button class="tab-btn" onclick="switchTab('auth_bootstrap', this)">
        🔐 Authentication Bootstrap ({len(auth_bootstrap)})
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
            <span>⚠️ Thất bại (không có 2xx)</span><span>{len(failed_apis)} API</span>
          </h3>
          <div style="display:flex;flex-wrap:wrap;gap:0.4rem">{failed_badges}</div>
        </div>
      </div>
    </div>

    <!-- Tab: Authentication bootstrap -->
    <div id="tab_auth_bootstrap" class="tab-panel">
      <h2 class="section-title">Authentication Bootstrap</h2>
      <p style="color:#94a3b8;margin-bottom:1rem">
        Các request setup được lưu để truy vết nhưng không được tính là finding hoặc security variant.
      </p>
      {auth_bootstrap_section}
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
  document.addEventListener('click', function(event) {{
    var link = event.target.closest('.api-link');
    if (!link) return;
    event.preventDefault();
    showApi(link.dataset.apiId || '');
  }});
</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[OK] Bao cao da duoc luu tai: {output_file}")
    print(f"     BOLA/IDOR: {bola_count}  |  Crash: {server_errors}  |  Tong phat hien: {total_findings}")


if __name__ == "__main__":
    generate_html_report()
