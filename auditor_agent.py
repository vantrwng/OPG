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
        classification:  str  = "INCONCLUSIVE",
        confidence:      float = 0.0,            # 0.0 – 1.0
        bola_type:       str  = "",              # "data_exposure" | "auth_bypass" | "privilege_escalation"
        evidence:        List[str] = None,
        reasoning:       str  = "",
        score_delta:     float = 0.0,            # Điểm cộng thêm vào beam score
        finding:         Optional[Dict] = None,
    ):
        self.is_bola        = is_bola
        self.classification = classification
        self.confidence     = confidence
        self.bola_type      = bola_type
        self.evidence       = evidence or []
        self.reasoning      = reasoning
        self.score_delta    = score_delta
        self.finding        = finding

    def __repr__(self):
        return (
            f"AuditResult(bola={self.is_bola}, cls={self.classification}, conf={self.confidence:.2f}, "
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
    VALID_CLASSIFICATIONS = {
        "CONFIRMED", "REJECTED", "INCONCLUSIVE", "NOT_TESTED", "INFRA_FAILURE",
    }

    def __init__(self, client: Optional[OllamaClient] = None):
        self._llm_enabled = client is not None or OLLAMA_ENABLED
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
        attack_status = attack_response.get("status", 0)
        strategy      = attack_variant_info.get("strategy", "unknown")
        description   = attack_variant_info.get("description", "")

        log.info(
            f"\033[94m[AuditorAgent]\033[0m Auditing {strategy} — "
            f"status={attack_status} desc={description[:60]}"
        )

        extra = attack_variant_info.get("extra", {}) or {}
        if not extra.get("confirmation_eligible", False):
            return AuditResult(
                is_bola=False,
                classification="NOT_TESTED",
                evidence=["No created foreign resource with authoritative provenance"],
                reasoning="Exploratory or guessed identifiers cannot confirm BOLA.",
            )
        if extra.get("preflight_ok") is False:
            return AuditResult(
                is_bola=False,
                classification="INFRA_FAILURE",
                evidence=[extra.get("preflight_reason", "Authentication preflight failed")],
            )
        if not self._valid_api_response(attack_response, api_node):
            return AuditResult(
                is_bola=False,
                classification="INCONCLUSIVE",
                evidence=["Response did not satisfy status/content-type/OpenAPI response checks"],
            )

        # A denial is authorization evidence only after a successful preflight.
        if attack_status == 0 or attack_status >= 400:
            # 500 từ attacker request là crash, không phải BOLA
            classification = "REJECTED" if attack_status in (401, 403, 404) else "INCONCLUSIVE"
            result = AuditResult(
                is_bola=False,
                classification=classification,
                confidence=1.0 if classification == "REJECTED" else 0.0,
                evidence=[f"Authorization boundary returned HTTP {attack_status}"],
            )
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

        deterministic_result = self._deterministic_authorization_analysis(
            attack_variant_info=attack_variant_info,
            attack_response=attack_response,
            baseline_response=baseline_response,
            state=state,
        )

        if deterministic_result["classification"] == "CONFIRMED":
            return self._decide(
                baseline_result=baseline_result,
                semantic_result=deterministic_result,
                attack_variant_info=attack_variant_info,
                attack_status=attack_status,
                api_node=api_node,
            )

        if not self._llm_enabled:
            return self._decide(
                baseline_result=baseline_result,
                semantic_result=deterministic_result,
                attack_variant_info=attack_variant_info,
                attack_status=attack_status,
                api_node=api_node,
            )

        # ── Step 17: Phân tích ngữ nghĩa JSON ─────────────────────────────────
        semantic_result = self._semantic_json_analysis(
            attack_response=attack_response,
            baseline_response=baseline_response,
            state=state,
            api_node=api_node,
            strategy=strategy,
        )
        # LLM output is advisory only. Confirmation belongs exclusively to the
        # deterministic provenance/fingerprint/state oracle above.
        if semantic_result.get("classification") in ("CONFIRMED", "SUSPECTED"):
            semantic_result["classification"] = "INCONCLUSIVE"
            semantic_result["confidence"] = min(float(semantic_result.get("confidence", 0.0)), 0.49)
        if deterministic_result.get("classification") == "INCONCLUSIVE":
            semantic_result = deterministic_result

        # ── Decision: vi phạm BOLA? ────────────────────────────────────────────
        return self._decide(
            baseline_result=baseline_result,
            semantic_result=semantic_result,
            attack_variant_info=attack_variant_info,
            attack_status=attack_status,
            api_node=api_node,
        )

    def _deterministic_authorization_analysis(
        self,
        attack_variant_info: Dict,
        attack_response: Dict,
        baseline_response: Optional[Dict],
        state: StateStore,
    ) -> Dict[str, Any]:
        """Conservative, replayable authorization oracle independent of an LLM."""
        body = attack_response.get("raw_response") or {}
        flat = self._flatten_json(body)
        current_id = state.get("user_id") or state.get("id")
        current_email = state.get("email")
        evidence: List[str] = []
        extra = attack_variant_info.get("extra", {}) or {}
        strategy = attack_variant_info.get("strategy", "")
        owner_actor_id = extra.get("owner_actor_id")
        attacker_actor_id = extra.get("attacker_actor_id") or state.get("actor_id")
        has_cross_actor_proof = bool(
            owner_actor_id and attacker_actor_id
            and str(owner_actor_id) != str(attacker_actor_id)
        )
        baseline_success = bool(
            baseline_response and baseline_response.get("status") in (200, 201, 202, 204)
        )
        provenance_ok = (
            extra.get("provenance") == "CREATED_RESPONSE"
            and extra.get("confirmation_eligible") is True
        )
        owner_role = str(extra.get("owner_role", "")).strip().casefold()
        attacker_role = str(extra.get("attacker_role", "")).strip().casefold()
        unknown_roles = {"", "unknown", "anonymous", "none", "null"}
        same_role = bool(
            owner_role not in unknown_roles
            and attacker_role not in unknown_roles
            and owner_role == attacker_role
        )
        repeated = int(extra.get("reproduction_count", 0) or 0) >= 2
        fingerprint_ok = bool(extra.get("fingerprint_verified"))
        method = str(extra.get("operation", "GET")).upper()
        mutation_verified = bool(extra.get("mutation_verified"))

        ownership_key = re.compile(
            r"(^|\.)(owner|user|account|created_by|customer)(_?id|email)?$",
            re.I,
        )
        for key, value in flat.items():
            if not ownership_key.search(str(key)):
                continue
            value_text = str(value).lower()
            differs_from_id = current_id is not None and value_text != str(current_id).lower()
            differs_from_email = current_email is not None and value_text != str(current_email).lower()
            if ("email" in str(key).lower() and differs_from_email) or (
                    "email" not in str(key).lower() and differs_from_id):
                evidence.append(
                    f"Response ownership field {key}={value!r} differs from current actor"
                )

        deterministic_success = fingerprint_ok if method == "GET" else mutation_verified
        if (baseline_success and has_cross_actor_proof and provenance_ok and same_role
                and repeated and deterministic_success
                and strategy in ("id_substitution", "reference_forge")):
            return {
                "classification": "CONFIRMED",
                "confidence": 0.95,
                "vulnerability_type": "BOLA",
                "evidence": evidence or ["Foreign resource fingerprint verified in 2/2 attempts"],
                "reasoning": "A same-role foreign resource test reproduced successfully in 2/2 attempts.",
            }

        owner_ctx = extra.get("owner_ctx", {}) or {}
        foreign_actor = owner_ctx.get("actor_id")
        current_actor = state.get("actor_id")
        is_cross_actor = bool(
            foreign_actor and current_actor and str(foreign_actor) != str(current_actor)
        )
        if evidence:
            return {
                "classification": "INCONCLUSIVE",
                "confidence": 0.7,
                "vulnerability_type": "BOLA",
                "evidence": evidence,
                "reasoning": "Foreign ownership is visible, but cross-actor policy proof is incomplete.",
            }
        if is_cross_actor and strategy in ("id_substitution", "reference_forge"):
            return {
                "classification": "INCONCLUSIVE",
                "confidence": 0.65,
                "vulnerability_type": "BOLA",
                "evidence": [
                    f"Actor {current_actor} received 2xx for a resource attributed to {foreign_actor}"
                ],
                "reasoning": "Foreign provenance exists, but the response lacks explicit ownership proof.",
            }

        technique = str(extra.get("technique", ""))
        if strategy == "param_pollution" and technique in (
                "mass_assignment", "privilege_escalation"):
            return {
                "classification": "INCONCLUSIVE",
                "confidence": 0.45,
                "vulnerability_type": "BOPLA",
                "evidence": ["Server accepted a privilege-related mutation with a 2xx response"],
                "reasoning": "A verification read is required before confirming the privilege change.",
            }

        return {
            "classification": "INCONCLUSIVE",
            "confidence": 0.0,
            "vulnerability_type": "NONE",
            "evidence": [],
            "reasoning": "No deterministic ownership or authorization evidence was found.",
        }

    @staticmethod
    def _valid_api_response(response: Dict[str, Any], api_node: Dict[str, Any]) -> bool:
        if not 200 <= int(response.get("status", 0) or 0) < 300:
            return True  # denial handling occurs after authentication preflight
        if response.get("successful") is False or response.get("schema_valid") is False:
            return False
        content_type = str(response.get("response_content_type", "")).casefold()
        text = str(response.get("response_text", "")).lstrip().casefold()
        if "text/html" in content_type or text.startswith("<!doctype html") or text.startswith("<html"):
            return False
        expected_json = bool(api_node.get("outputs"))
        if expected_json and response.get("raw_response") is None:
            return False
        return True

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
        Dùng Llama để phân tích ngữ nghĩa response với model 3-state classification.
        Không kết luận vội vàng, yêu cầu Evidence mạnh (Ownership).
        """
        attack_body = attack_response.get("raw_response") or {}
        if not attack_body:
            return {"classification": "INCONCLUSIVE", "confidence": 0.0, "reasoning": "Empty response body"}

        # Build context cho LLM
        own_context = {
            "user_id":  state.get("user_id") or state.get("id"),
            "email":    state.get("email"),
            "username": state.get("username") or state.get("name"),
            "role":     state.get("role") or state.get("user_role") or "normal",
        }
        own_context = {k: v for k, v in own_context.items() if v}

        # Giới hạn kích thước body (tránh token limit)
        attack_body_str   = json.dumps(attack_body,   ensure_ascii=False)[:2000]

        prompt = f"""You are auditing an API for BOLA/IDOR/BFLA vulnerabilities.

API Endpoint: {api_node.get('method')} {api_node.get('path')}
Attack Strategy used: {strategy}

Current Authenticated User Context:
{json.dumps(own_context, indent=2)}

Attack Response (Server replied to the attacker):
{attack_body_str}

YOUR TASK:
Determine if the Attack Response proves a vulnerability (BOLA/BFLA).
CRITICAL RULES for BOLA:
- Do NOT assume BOLA just because HTTP is 200.
- Do NOT assume BOLA just because there is no 'user_id' in the response.
- BOLA is CONFIRMED *only* if there is STRONG EVIDENCE that the returned object/resource belongs to a DIFFERENT user than the Current User.
- If there is NO ownership information available, classification MUST BE 'INCONCLUSIVE'.

CRITICAL RULES for BFLA:
- Do NOT assume BFLA just because the attacker sent 'isAdmin=true'.
- BFLA is CONFIRMED *only* if the server actually performed an administrative action for a normal user.

Respond ONLY with a JSON object in this exact format:
{{
  "classification": "CONFIRMED", // or "SUSPECTED", or "INCONCLUSIVE"
  "vulnerability_type": "BOLA", // or BFLA, BROKEN_ACCESS_CONTROL, MASS_ASSIGNMENT, PRIVILEGE_ESCALATION, NONE, UNKNOWN
  "confidence": 0.0, // Float 0.0 to 1.0
  "evidence": ["list of explicit evidence strings found in the response"],
  "reason": "Detailed explanation of why it is CONFIRMED, SUSPECTED, or INCONCLUSIVE."
}}"""

        result = self.client.auditor(prompt, system=self.SYSTEM_PROMPT, temperature=0.1)

        if not result:
            log.warning("[AuditorAgent] LLM semantic analysis returned None")
            return {"classification": "INCONCLUSIVE", "confidence": 0.0, "reasoning": "LLM unavailable"}

        log.info(f"\033[94m[SECURITY ANALYSIS]\033[0m Class: {result.get('classification')}, VulnType: {result.get('vulnerability_type')}")

        return {
            "classification": result.get("classification", "INCONCLUSIVE"),
            "confidence":     float(result.get("confidence", 0.0)),
            "vulnerability_type": result.get("vulnerability_type", "NONE"),
            "evidence":       result.get("evidence", []),
            "reasoning":      result.get("reason", ""),
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
        Tổng hợp kết quả từ LLM semantic classification + baseline diff.
        Tuân thủ 3-state classification.
        """
        classification = semantic_result.get("classification", "INCONCLUSIVE")
        confidence     = semantic_result.get("confidence", 0.0)
        bola_type      = semantic_result.get("vulnerability_type", "NONE")
        reasoning      = semantic_result.get("reasoning", "")
        evidence       = (
            semantic_result.get("evidence", []) +
            baseline_result.get("details", [])
        )
        
        # Only CONFIRMED results become vulnerabilities. SUSPECTED is retained
        # for reporting/triage but must not bias beam scoring as a finding.
        is_bola = classification == "CONFIRMED"
        
        if classification == "CONFIRMED":
            score_delta = self.STRONG_BOLA_BONUS
            severity = "HIGH"
        else:
            score_delta = 0.0
            severity = "INFO"

        if is_bola:
            finding = self._build_finding(
                bola_type=bola_type,
                confidence=confidence,
                evidence=evidence,
                reasoning=reasoning,
                attack_variant_info=attack_variant_info,
                api_node=api_node,
                attack_status=attack_status,
                severity=severity,
            )
            log.warning(
                f"\033[91m[FINAL CLASSIFICATION]\033[0m VULNERABILITY {classification} "
                f"type={bola_type} conf={confidence:.2f}"
            )
            return AuditResult(
                is_bola=True,
                classification=classification,
                confidence=confidence,
                bola_type=bola_type,
                evidence=evidence,
                reasoning=reasoning,
                score_delta=score_delta,
                finding=finding,
            )

        # ── Not BOLA / Inconclusive ───────────────────────────────────────────
        log.info(f"\033[92m[FINAL CLASSIFICATION]\033[0m {classification} (conf={confidence:.2f})")
        return AuditResult(is_bola=False, classification=classification, confidence=confidence)

    @staticmethod
    def _build_finding(
        bola_type:           str,
        confidence:          float,
        evidence:            List[str],
        reasoning:           str,
        attack_variant_info: Dict,
        api_node:            Dict,
        attack_status:       int,
        severity:            str = "HIGH",
    ) -> Dict:
        """Tạo finding dict để ghi vào KnowledgeMemory."""
        normalized_type = bola_type.upper()
        finding_type = normalized_type if normalized_type in {
            "BOLA", "BFLA", "BOPLA", "BROKEN_ACCESS_CONTROL"
        } else f"BOLA/{normalized_type}"
        return {
            "type":        finding_type,
            "severity":    severity,
            "confidence":  round(confidence, 2),
            "api":         api_node.get("id", ""),
            "method":      api_node.get("method", ""),
            "path":        api_node.get("path", ""),
            "status":      attack_status,
            "strategy":    attack_variant_info.get("strategy", ""),
            "description": attack_variant_info.get("description", ""),
            "evidence":    evidence[:10],   # Giới hạn 10 evidence items
            "reasoning":   reasoning,
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
