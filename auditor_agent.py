"""
auditor_agent.py
================
Auditor Agent chạy Llama 3.1 8B để phát hiện vi phạm BOLA/IDOR
(Steps 16, 17, 18, 19, 20 trong sơ đồ).

Flow:
  [Response Attacker]
       │
       ├─ (16) So sánh với Baseline (structural diff)
       │
       ├─ (17) Phân tích ngữ nghĩa JSON (hỏi Llama: "có data của người khác không?")
       │
       └─ Vi phạm BOLA/IDOR?
              ├── Có  → (18) Tăng score + (20) Ghi Finding
              └── Không → (19) Chọn endpoint tiếp theo
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ollama_client import OllamaClient, get_ollama_client, OLLAMA_ENABLED
from state_store import StateStore

log = logging.getLogger("auditor_agent")


class AuditResult:
    """Kết quả audit cho một attack variant."""

    def __init__(
        self,
        is_bola:         bool,
        confidence:      float,          # 0.0 – 1.0
        bola_type:       str  = "",      # "data_exposure" | "auth_bypass" | "privilege_escalation"
        evidence:        List[str] = None,
        score_delta:     float = 0.0,    # Điểm cộng thêm vào beam score
        finding:         Optional[Dict] = None,
    ):
        self.is_bola     = is_bola
        self.confidence  = confidence
        self.bola_type   = bola_type
        self.evidence    = evidence or []
        self.score_delta = score_delta
        self.finding     = finding

    def __repr__(self):
        return (
            f"AuditResult(bola={self.is_bola}, conf={self.confidence:.2f}, "
            f"type={self.bola_type}, score_delta={self.score_delta:+.1f})"
        )


class AuditorAgent:
    """
    Auditor Agent: Llama 3.1 8B.

    So sánh response của Attacker với baseline,
    rồi phân tích ngữ nghĩa JSON để xác định vi phạm BOLA/IDOR.
    """

    SYSTEM_PROMPT = (
        "You are a senior API security auditor specializing in OWASP API Top 10. "
        "Your task is to detect BOLA (Broken Object Level Authorization) and IDOR "
        "vulnerabilities by analyzing API responses. Be precise, conservative, and "
        "avoid false positives. Only flag clear violations."
    )

    # Score delta khi phát hiện BOLA (step 18)
    BOLA_SCORE_BONUS = 150.0
    STRONG_BOLA_BONUS = 200.0

    def __init__(self, client: Optional[OllamaClient] = None):
        self.client = client or get_ollama_client()

    # ── Entry point chính ─────────────────────────────────────────────────────

    def audit(
        self,
        attack_variant_info: Dict,     # {strategy, description, extra, ...}
        attack_response:     Dict,     # exec_result từ RequestExecutor
        baseline_response:   Optional[Dict],  # exec_result của request hợp lệ
        state:               StateStore,
        api_node:            Dict,
    ) -> AuditResult:
        """
        Audit một attack variant response.

        Args:
            attack_variant_info: Metadata của AttackVariant (strategy, description, ...)
            attack_response:     exec_result từ RequestExecutor khi chạy attack
            baseline_response:   exec_result từ RequestExecutor khi chạy request hợp lệ
            state:               StateStore hiện tại (own_id, email, ...)
            api_node:            Thông tin API

        Returns:
            AuditResult
        """
        if not OLLAMA_ENABLED:
            return AuditResult(is_bola=False, confidence=0.0)

        attack_status = attack_response.get("status", 0)
        strategy      = attack_variant_info.get("strategy", "unknown")
        description   = attack_variant_info.get("description", "")

        log.info(
            f"\033[94m[AuditorAgent]\033[0m Auditing {strategy} — "
            f"status={attack_status} desc={description[:60]}"
        )

        # Nếu attack trả về lỗi (4xx/5xx) → không phải BOLA (nhưng ghi nhận 500)
        if attack_status == 0 or attack_status >= 400:
            # 500 từ attacker request là crash, không phải BOLA
            result = AuditResult(is_bola=False, confidence=0.0)
            if attack_status >= 500:
                result.finding = {
                    "type":     "Crash/500 (Attacker)",
                    "strategy": strategy,
                    "status":   attack_status,
                    "desc":     description,
                }
            return result

        # ── Step 16: So sánh với Baseline ─────────────────────────────────────
        baseline_result = self._compare_with_baseline(
            attack_response=attack_response,
            baseline_response=baseline_response,
            state=state,
        )

        # ── Step 17: Phân tích ngữ nghĩa JSON ─────────────────────────────────
        semantic_result = self._semantic_json_analysis(
            attack_response=attack_response,
            baseline_response=baseline_response,
            state=state,
            api_node=api_node,
            strategy=strategy,
        )

        # ── Decision: vi phạm BOLA? ────────────────────────────────────────────
        return self._decide(
            baseline_result=baseline_result,
            semantic_result=semantic_result,
            attack_variant_info=attack_variant_info,
            attack_status=attack_status,
            api_node=api_node,
        )

    # ── Step 16: So sánh với Baseline ─────────────────────────────────────────

    def _compare_with_baseline(
        self,
        attack_response:   Dict,
        baseline_response: Optional[Dict],
        state:             StateStore,
    ) -> Dict[str, Any]:
        """
        So sánh cấu trúc/nội dung của attack response với baseline.

        Trả về dict kết quả phân tích:
          - same_status:       Cùng HTTP status code?
          - data_differs:      Response body có khác không?
          - foreign_data_hint: Có dữ liệu khác user không (heuristic)?
          - confidence:        Độ tin cậy sơ bộ
        """
        result = {
            "same_status":       False,
            "data_differs":      False,
            "foreign_data_hint": False,
            "confidence":        0.0,
            "details":           [],
        }

        attack_status   = attack_response.get("status", 0)
        attack_body     = attack_response.get("raw_response") or {}
        attack_text     = attack_response.get("response_text", "")

        if not baseline_response:
            # Không có baseline: dùng heuristic dựa trên state
            result["confidence"] = 0.3
            result["details"].append("No baseline available — using heuristic only")
            # Heuristic: response 200 với data có vẻ nhạy cảm
            if attack_status in (200, 201):
                result["same_status"] = True
                own_id    = str(state.get("user_id") or "")
                own_email = str(state.get("email") or "").lower()
                # Nếu response chứa ID/email khác với own → hint
                if own_email and own_email not in attack_text.lower() and len(attack_text) > 50:
                    result["foreign_data_hint"] = True
                    result["confidence"] = 0.5
                    result["details"].append("Response data doesn't match own user email")
            return result

        baseline_status = baseline_response.get("status", 0)
        baseline_body   = baseline_response.get("raw_response") or {}

        # Cùng status code?
        result["same_status"] = (attack_status == baseline_status)
        if not result["same_status"]:
            result["details"].append(
                f"Status mismatch: baseline={baseline_status}, attack={attack_status}"
            )
            return result  # Khác status → không phải BOLA điển hình

        # So sánh nội dung JSON
        if isinstance(attack_body, dict) and isinstance(baseline_body, dict):
            diff = self._json_diff(baseline_body, attack_body)
            if diff:
                result["data_differs"] = True
                result["details"].extend(diff[:5])   # Tối đa 5 diff items
                result["confidence"]   = 0.6

                # Kiểm tra xem các field khác có chứa "foreign" data không
                own_id    = str(state.get("user_id") or state.get("id") or "")
                own_email = str(state.get("email") or "").lower()

                attack_flat = self._flatten_json(attack_body)
                for k, v in attack_flat.items():
                    v_str = str(v).lower()
                    if own_email and own_email in v_str:
                        continue  # Đây là data của mình, bỏ qua
                    if re.search(r"@[a-z0-9.-]+\.[a-z]{2,}", v_str):
                        result["foreign_data_hint"] = True
                        result["confidence"] = 0.75
                        result["details"].append(f"Foreign email found in response: {v_str[:40]}")
                        break
                    if own_id and re.search(r"(_id|Id)$", k, re.I) and v_str != own_id and v_str.isdigit():
                        result["foreign_data_hint"] = True
                        result["confidence"] = 0.7
                        result["details"].append(f"Foreign ID in response: {k}={v}")
                        break
        else:
            # Không parse được JSON: so sánh text length
            attack_len   = len(attack_text)
            baseline_len = len(baseline_response.get("response_text", ""))
            if abs(attack_len - baseline_len) > 50:
                result["data_differs"] = True
                result["confidence"]   = 0.4
                result["details"].append(
                    f"Response length differs: baseline={baseline_len}, attack={attack_len}"
                )

        return result

    @staticmethod
    def _json_diff(base: Dict, attack: Dict, prefix: str = "") -> List[str]:
        """Tìm các field có giá trị khác nhau giữa 2 JSON."""
        diffs = []
        for k in set(list(base.keys()) + list(attack.keys())):
            full_key = f"{prefix}.{k}" if prefix else k
            bv = base.get(k)
            av = attack.get(k)
            if bv != av:
                if isinstance(bv, dict) and isinstance(av, dict):
                    diffs.extend(AuditorAgent._json_diff(bv, av, full_key))
                else:
                    diffs.append(f"{full_key}: baseline={str(bv)[:30]} → attack={str(av)[:30]}")
        return diffs

    @staticmethod
    def _flatten_json(obj: Any, result: Dict = None) -> Dict:
        if result is None:
            result = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int, float)):
                    result[k] = v
                elif isinstance(v, (dict, list)):
                    AuditorAgent._flatten_json(v, result)
        elif isinstance(obj, list):
            for item in obj:
                AuditorAgent._flatten_json(item, result)
        return result

    # ── Step 17: Phân tích ngữ nghĩa JSON ─────────────────────────────────────

    def _semantic_json_analysis(
        self,
        attack_response:   Dict,
        baseline_response: Optional[Dict],
        state:             StateStore,
        api_node:          Dict,
        strategy:          str,
    ) -> Dict[str, Any]:
        """
        Dùng Llama 3.1 8B để phân tích ngữ nghĩa của response.
        Hỏi: "Response này có chứa data của người khác không?"
        """
        attack_body = attack_response.get("raw_response") or {}
        if not attack_body:
            return {"is_bola": False, "confidence": 0.0, "reasoning": "Empty response body"}

        # Build context cho LLM
        own_context = {
            "user_id":  state.get("user_id") or state.get("id"),
            "email":    state.get("email"),
            "username": state.get("username") or state.get("name"),
        }
        # Lọc None
        own_context = {k: v for k, v in own_context.items() if v}

        baseline_body = {}
        if baseline_response:
            baseline_body = baseline_response.get("raw_response") or {}

        # Giới hạn kích thước body để không quá dài
        attack_body_str   = json.dumps(attack_body,   ensure_ascii=False)[:1500]
        baseline_body_str = json.dumps(baseline_body, ensure_ascii=False)[:800]

        prompt = f"""You are auditing an API for BOLA (Broken Object Level Authorization) vulnerabilities.

API Endpoint: {api_node.get('method')} {api_node.get('path')}
Attack Strategy: {strategy}

Current User Context (the legitimate user who owns the token):
{json.dumps(own_context, indent=2)}

Baseline Response (legitimate user's own data):
{baseline_body_str if baseline_body_str != '{{}}' else "(not available)"}

Attack Response (potentially accessing another user's data):
{attack_body_str}

Analyze whether the Attack Response contains data belonging to a DIFFERENT user than the Current User.

Consider:
1. Do the IDs, emails, names, or other PII in the response match the Current User's context?
2. Is sensitive data exposed that shouldn't be accessible?
3. Does the response structure suggest unauthorized data access?

Respond with JSON:
{{
  "is_bola": true/false,
  "confidence": 0.0-1.0,
  "bola_type": "data_exposure" | "auth_bypass" | "privilege_escalation" | "none",
  "evidence": ["list of specific evidence strings"],
  "reasoning": "brief explanation"
}}"""

        result = self.client.auditor(prompt, system=self.SYSTEM_PROMPT, temperature=0.05)

        if not result:
            log.warning("[AuditorAgent] LLM semantic analysis returned None — using heuristic")
            return {"is_bola": False, "confidence": 0.0, "reasoning": "LLM unavailable"}

        return {
            "is_bola":    bool(result.get("is_bola", False)),
            "confidence": float(result.get("confidence", 0.0)),
            "bola_type":  result.get("bola_type", "none"),
            "evidence":   result.get("evidence", []),
            "reasoning":  result.get("reasoning", ""),
        }

    # ── Decision ───────────────────────────────────────────────────────────────

    def _decide(
        self,
        baseline_result:     Dict,
        semantic_result:     Dict,
        attack_variant_info: Dict,
        attack_status:       int,
        api_node:            Dict,
    ) -> AuditResult:
        """
        Tổng hợp kết quả từ baseline diff + semantic analysis.
        Ra quyết định cuối cùng: BOLA hay không.

        Rule:
          - semantic confidence >= 0.7  → IS BOLA (strong)
          - semantic confidence >= 0.5 AND baseline hint → IS BOLA (medium)
          - Else → NOT BOLA
        """
        sem_conf   = semantic_result.get("confidence", 0.0)
        sem_bola   = semantic_result.get("is_bola", False)
        base_hint  = baseline_result.get("foreign_data_hint", False)
        base_conf  = baseline_result.get("confidence", 0.0)
        bola_type  = semantic_result.get("bola_type", "none")
        evidence   = (
            semantic_result.get("evidence", []) +
            baseline_result.get("details", [])
        )

        # ── Strong BOLA ────────────────────────────────────────────────────────
        if sem_bola and sem_conf >= 0.7:
            score_delta = self.STRONG_BOLA_BONUS
            finding = self._build_finding(
                bola_type=bola_type,
                confidence=sem_conf,
                evidence=evidence,
                attack_variant_info=attack_variant_info,
                api_node=api_node,
                attack_status=attack_status,
                severity="HIGH",
            )
            log.warning(
                f"\033[91m[AuditorAgent] BOLA DETECTED (HIGH)\033[0m "
                f"type={bola_type} conf={sem_conf:.2f}"
            )
            return AuditResult(
                is_bola=True,
                confidence=sem_conf,
                bola_type=bola_type,
                evidence=evidence,
                score_delta=score_delta,
                finding=finding,
            )

        # ── Medium BOLA ────────────────────────────────────────────────────────
        combined_conf = 0.6 * sem_conf + 0.4 * base_conf
        if sem_bola and combined_conf >= 0.5 and base_hint:
            score_delta = self.BOLA_SCORE_BONUS
            finding = self._build_finding(
                bola_type=bola_type,
                confidence=combined_conf,
                evidence=evidence,
                attack_variant_info=attack_variant_info,
                api_node=api_node,
                attack_status=attack_status,
                severity="MEDIUM",
            )
            log.warning(
                f"\033[93m[AuditorAgent] BOLA DETECTED (MEDIUM)\033[0m "
                f"type={bola_type} combined_conf={combined_conf:.2f}"
            )
            return AuditResult(
                is_bola=True,
                confidence=combined_conf,
                bola_type=bola_type,
                evidence=evidence,
                score_delta=score_delta,
                finding=finding,
            )

        # ── Not BOLA ──────────────────────────────────────────────────────────
        log.info(
            f"[AuditorAgent] No BOLA detected "
            f"(sem_conf={sem_conf:.2f}, base_hint={base_hint})"
        )
        return AuditResult(is_bola=False, confidence=sem_conf)

    @staticmethod
    def _build_finding(
        bola_type:           str,
        confidence:          float,
        evidence:            List[str],
        attack_variant_info: Dict,
        api_node:            Dict,
        attack_status:       int,
        severity:            str = "HIGH",
    ) -> Dict:
        """Tạo finding dict để ghi vào KnowledgeMemory."""
        return {
            "type":        f"BOLA/{bola_type.upper()}",
            "severity":    severity,
            "confidence":  round(confidence, 2),
            "api":         api_node.get("id", ""),
            "method":      api_node.get("method", ""),
            "path":        api_node.get("path", ""),
            "status":      attack_status,
            "strategy":    attack_variant_info.get("strategy", ""),
            "description": attack_variant_info.get("description", ""),
            "evidence":    evidence[:10],   # Giới hạn 10 evidence items
            "extra":       attack_variant_info.get("extra", {}),
        }

    # ── Batch audit ────────────────────────────────────────────────────────────

    def audit_batch(
        self,
        attack_variants_results: List[Tuple[Dict, Dict]],  # [(variant_info, exec_result)]
        baseline_response:       Optional[Dict],
        state:                   StateStore,
        api_node:                Dict,
    ) -> List[AuditResult]:
        """
        Audit nhiều attack variants cùng lúc.

        Args:
            attack_variants_results: List of (variant_info_dict, exec_result_dict)
            baseline_response:       exec_result của request hợp lệ

        Returns:
            List[AuditResult]
        """
        results = []
        for variant_info, exec_result in attack_variants_results:
            audit_result = self.audit(
                attack_variant_info=variant_info,
                attack_response=exec_result,
                baseline_response=baseline_response,
                state=state,
                api_node=api_node,
            )
            results.append(audit_result)

            # Dừng sớm nếu đã tìm thấy BOLA với confidence cao
            if audit_result.is_bola and audit_result.confidence >= 0.8:
                log.info("[AuditorAgent] Early stop — high-confidence BOLA found")
                break

        return results
