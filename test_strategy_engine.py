import json
import re
import math
import asyncio
import logging
import uuid
from state_store import StateStore
from runtime_executor import RequestExecutor
from knowledge_memory import KnowledgeMemory
from local_mutator import AsyncFuzzEngine
from attack_store import AttackStore
from state_store import MultiActorContextStore
from response_outcome import result_succeeded
from field_semantics import is_reference_field, normalize_field_name
from actor_bootstrapper import ActorBootstrapper
from authorization_experiment import AuthorizationExperimentPlanner
from reference_engine import ObservableMutator, ProvenanceChain, ProvenanceLevel
from resource_provisioner import GenericResourceProvisioner

# ── Agent imports (optional — graceful fallback if Ollama not available) ─────────
_AGENTS_AVAILABLE = False
_AGENTS_IMPORT_ERROR = ""
try:
    from attacker_agent import AttackerAgent, AttackVariant
    from auditor_agent import AuditorAgent, AuditResult
    _AGENTS_AVAILABLE = True
except ImportError as exc:
    _AGENTS_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

log = logging.getLogger("strategy_engine")

def jaccard_similarity(list1, list2):
    s1 = set(list1)
    s2 = set(list2)
    union_len = len(s1.union(s2))
    if union_len == 0: return 0
    return len(s1.intersection(s2)) / union_len

class HeuristicScorer:
    def __init__(self):
        self.common_statuses = {200, 201, 204, 401, 403, 404}

    def calculate_score(self, response_mock, depth, visit_count, already_found: bool = False):
        score = 0
        status = response_mock.get('status', 200)

        if response_mock.get('server_error'):
            score += 10 if already_found else 100
        if response_mock.get('auth_anomaly'):
            score += 5 if already_found else 80
        if response_mock.get('state_transition'):
            score += 40
        if status not in self.common_statuses:
            score += 20
        if response_mock.get('response_diff', False):
            score += 10
        if not result_succeeded(response_mock):
            score -= 15
        if response_mock.get("auth_state_mismatch"):
            score -= 30

        score += min(depth, 10) * 2

        if status == 400: score -= 10
        if status == 403: score -= 25

        exploration_bonus = 50 / math.sqrt(visit_count) if visit_count > 0 else 50
        score += exploration_bonus

        return score

    def calculate_diversity_penalty(self, current_chain, current_beam):
        penalty = 0
        for b in current_beam:
            sim = jaccard_similarity(current_chain, b['chain'])
            if sim > 0.6:
                penalty += 50 * sim
        return penalty

class CoverageBucketManager:
    def __init__(self, top_k=5):
        self.top_k = top_k
        self.buckets = {
            'auth': [],
            'admin': [],
            'crud': [],
            'other': []
        }

    def categorize(self, api_id):
        expanded = re.sub(r'([a-z])([A-Z])', r'\1 \2', api_id)
        tokens = set(re.split(r'[_\-\s/]', expanded.lower()))
        if tokens & {'login', 'signup', 'auth', 'token', 'password'}:
            return 'auth'
        elif 'admin' in tokens:
            return 'admin'
        elif tokens & {'create', 'update', 'delete', 'post', 'put', 'add'}:
            return 'crud'
        else:
            return 'other'

    def add_to_bucket(self, chain, score, state=None, vulnerabilities=None):
        last_api = chain[-1]
        bucket_name = self.categorize(last_api)
        
        self.buckets[bucket_name].append({
            'chain': list(chain), 
            'score': score, 
            'state': state,
            'vulnerabilities': vulnerabilities or []
        })
        self.buckets[bucket_name].sort(key=lambda x: x['score'], reverse=True)
        self.buckets[bucket_name] = self.buckets[bucket_name][:self.top_k]

    def get_all_beams(self):
        all_beams = []
        for v in self.buckets.values():
            all_beams.extend(v)
        return all_beams

class TestStrategyEngine:
    __test__ = False

    def __init__(self, operations, adjacency_list, request_executor, graph_builder,
                 knowledge_memory, beam_width=5, enable_security_testing=False,
                 attack_store=None):
        self.operations = operations
        self.adjacency_list = adjacency_list
        self.executor = request_executor
        self.graph_builder = graph_builder
        self.memory = knowledge_memory
        
        self.scorer = HeuristicScorer()
        self.beam_width = beam_width
        self.enable_security_testing = enable_security_testing
        self._pipeline_phase = "workflow"
        # One confirmed baseline per (actor, endpoint). Tokens remain in-memory
        # only and are never exported through KnowledgeMemory.
        self._valid_workflows = {}
        self.actor_contexts = MultiActorContextStore()
        self.operations_map = {op['id']: op for op in self.operations}
        self.authorization_planner = AuthorizationExperimentPlanner(self.operations)
        self.authorization_experiments = self.authorization_planner.plan()
        for operation in self.operations:
            self.memory.mark_endpoint_discovered(str(operation.get("id", "unknown")))

        # Shared by beams in this engine run, but never across independent runs.
        self.attack_store: AttackStore = attack_store or AttackStore()
        self.resource_provisioner = GenericResourceProvisioner(
            self.operations, self.authorization_planner, self.executor,
            self.attack_store,
        )
        self._last_provisioning_failure = ""

        # ── Agent instances ─────────────────────────────────────────────────
        if _AGENTS_AVAILABLE and self.enable_security_testing:
            self._attacker = AttackerAgent(attack_store=self.attack_store)
            self._auditor  = AuditorAgent()
            log.info("[Engine] ✅ Security mode: Attacker + Auditor enabled")
        else:
            self._attacker = None
            self._auditor  = None
            log.info("[Engine] Workflow mode: valid requests only; attacker disabled")
            if self.enable_security_testing and _AGENTS_IMPORT_ERROR:
                self.memory.record_security_observation({
                    "classification": "NOT_TESTED", "type": "PIPELINE",
                    "reason_code": "generation_failed",
                    "reasoning": f"Security agents could not be imported: {_AGENTS_IMPORT_ERROR}",
                })
        
        self.incoming_edges = {}
        for api_out, edges in self.adjacency_list.items():
            for edge in edges:
                api_in = edge['to']
                if api_in not in self.incoming_edges:
                    self.incoming_edges[api_in] = []
                self.incoming_edges[api_in].append({
                    'from': api_out,
                    'dependencies': edge.get('dependencies', [])
                })

    def resolve_missing_dependencies(self, api_node, state, current_chain,
                                       recursion_depth=0, visited=None, budget=None):
        MAX_RECURSION = 4        # Hướng 5: tăng từ 2 lên 4 thay vì cố định
        MAX_PROVIDER_CALLS = 6   # Hướng 5: giới hạn tổng số request phụ

        if visited is None:
            visited = set()
        if budget is None:
            budget = [MAX_PROVIDER_CALLS]  # dùng list để pass by reference

        if recursion_depth >= MAX_RECURSION or budget[0] <= 0:
            return

        api_id = api_node.get('id')
        if api_id in visited:
            return
        visited.add(api_id)

        inputs_schema = api_node.get("inputs", {})
        if not inputs_schema:
            return

        def _norm(name):
            return normalize_field_name(name)

        # Required/path inputs are dependencies as before.  Optional reference
        # fields in write bodies are dependencies too: many real-world specs
        # forget to include foreign keys in `required`.
        missing_fields = []
        missing_field_meta = {}
        state_keys_norm = set(_norm(k) for k in state.memory.keys())
        method = str(api_node.get("method", "GET")).upper()

        for field_name, meta in inputs_schema.items():
            if not isinstance(meta, dict):
                continue

            is_required = meta.get("required", False)
            location    = meta.get("in", "body")

            is_write_body_reference = (
                method in {"POST", "PUT", "PATCH"}
                and str(location).lower() == "body"
                and is_reference_field(field_name, meta)
            )
            if not is_required and location != "path" and not is_write_body_reference:
                continue

            original = meta.get("original", field_name)
            orig_norm = _norm(original)
            fld_norm  = _norm(field_name)

            if orig_norm not in state_keys_norm and fld_norm not in state_keys_norm:
                missing_fields.append(orig_norm)
                missing_field_meta[orig_norm] = meta

        if not missing_fields:
            return

        providers = self.incoming_edges.get(api_id, [])

        for missing_field in missing_fields:
            if budget[0] <= 0:
                break

            # ── Hướng 2: Xây danh sách candidate + sort theo confidence + runtime score ──
            # FIX: Dùng `provider_tried` riêng cho từng field thay vì dùng chung `visited`.
            # `visited` chỉ dùng làm recursion-guard (ngăn vòng lặp đệ quy vô tận),
            # không nên block provider phục vụ các missing_field khác ở cùng level.
            provider_tried: set = set()
            candidates = []
            for provider in providers:
                if provider['from'] in visited or provider['from'] in current_chain:
                    continue
                for dep in provider.get('dependencies', []):
                    if _norm(dep.get('consumer_field', '')) != missing_field:
                        continue

                    provider_id = provider['from']
                    static_conf = dep.get('confidence', 0.0)

                    # Runtime score từ edge_feedback
                    edge_key = f"{provider_id}->{api_id}"
                    fb = self.memory.edge_feedback.get(edge_key, {})
                    s  = fb.get('success', 0)
                    f  = fb.get('failure', 0)
                    runtime_score = (s + 1) / (s + f + 2)  # Laplace smoothing
                    combined = 0.7 * static_conf + 0.3 * runtime_score

                    # Exact field handoff outranks a higher-confidence fuzzy
                    # relation (e.g. resourceList -> resourceId). This remains
                    # domain-neutral and uses only graph/schema semantics.
                    producer_field = dep.get('producer_field', '')
                    exact_match = _norm(producer_field) == missing_field
                    if exact_match:
                        combined += 0.35

                    provider_node = self.operations_map.get(provider_id, {})
                    if provider_node.get("potentially_destructive"):
                        continue
                    output_meta = None
                    for output_name, candidate_meta in (provider_node.get("outputs", {}) or {}).items():
                        candidate_meta = candidate_meta if isinstance(candidate_meta, dict) else {}
                        candidate_names = (
                            output_name,
                            candidate_meta.get("original", output_name),
                            candidate_meta.get("contextual_name", output_name),
                        )
                        if any(_norm(name) == _norm(producer_field) for name in candidate_names):
                            output_meta = candidate_meta
                            break
                    consumer_type = str(missing_field_meta.get(missing_field, {}).get("type", "")).lower()
                    producer_type = str((output_meta or {}).get("type", "")).lower()
                    if consumer_type and producer_type:
                        combined += 0.10 if consumer_type == producer_type else -0.25

                    candidates.append({
                        'provider_id': provider_id,
                        'dep':         dep,
                        'score':       combined
                    })

            # Sắp xếp: provider tốt nhất lên trước
            candidates.sort(key=lambda x: x['score'], reverse=True)

            resolved = False
            for cand in candidates:
                if budget[0] <= 0:
                    break

                provider_id   = cand['provider_id']
                dep           = cand['dep']
                provider_node = self.operations_map.get(provider_id)
                if not provider_node:
                    continue
                if self._has_authenticated_actor(state) and self._is_registration_api(provider_node):
                    continue

                # FIX: Không thử lại cùng provider cho cùng field trong một vòng lặp.
                if provider_id in provider_tried:
                    continue
                provider_tried.add(provider_id)

                indent = '  ' * (recursion_depth + 1)
                print(f"{indent}[Sub-task] {api_id} thiếu '{missing_field}'. "
                      f"Thử provider '{provider_id}' (score={cand['score']:.2f})...")

                edge_deps = [{'producer_field': dep['producer_field'],
                              'consumer_field': dep['consumer_field']}]

                # ── Đệ quy resolve dependencies của chính provider ────────────
                self.resolve_missing_dependencies(
                    provider_node, state, current_chain,
                    recursion_depth + 1, visited, budget
                )

                exec_result = self.executor.execute_request(
                    api_node=provider_node,
                    current_state=state,
                    edge_deps=edge_deps
                )
                budget[0] -= 1

                # ── Hướng 3: Ghi nhận request của provider vào KnowledgeMemory ──
                self.memory.record_request(
                    api_id=provider_id,
                    method=provider_node.get("method", "GET").upper(),
                    path=exec_result.get("url", provider_node.get("path", "/")),
                    status=exec_result["status"],
                    chain=list(current_chain),
                    response_text=exec_result.get("response_text", ""),
                    request_payload=exec_result.get("sent_payload", {}),
                    payload_source=exec_result.get("payload_source", "NONE"),
                    repair_reason=exec_result.get("repair_reason", ""),
                    repair_history=exec_result.get("repair_history", []),
                    sent_headers=exec_result.get("sent_headers", {}),
                    sent_query=exec_result.get("sent_query", {}),
                    sent_cookies=exec_result.get("sent_cookies", {}),
                    actor_id=exec_result.get("actor_id", state.get("actor_id", "default")),
                    successful=exec_result.get("successful"),
                    outcome_reason=exec_result.get("outcome_reason", ""),
                    auth_recovery=exec_result.get("auth_recovery", {}),
                    auth_context=exec_result.get("auth_context", {}),
                    sent_files=exec_result.get("sent_files", {}),
                    elapsed_ms=exec_result.get("elapsed_ms"),
                )

                if result_succeeded(exec_result):
                    provider_chain = list(current_chain)
                    provider_chain.insert(max(0, len(provider_chain) - 1), provider_id)
                    self._capture_valid_workflow(
                        api_node=provider_node,
                        state=state,
                        exec_result=exec_result,
                        chain=provider_chain,
                    )
                    refreshed_state_keys = {_norm(k) for k in state.memory.keys()}
                    if missing_field in refreshed_state_keys:
                        # Provider executes before the current consumer, so keep
                        # the reported chain in actual execution order.
                        insert_at = max(0, len(current_chain) - 1)
                        current_chain.insert(insert_at, provider_id)
                        resolved = True
                        print(f"{indent}[+] Resolve '{missing_field}' thành công via '{provider_id}'!")
                        break
                    print(
                        f"{indent}[-] Provider '{provider_id}' trả 2xx nhưng không sinh "
                        f"giá trị '{missing_field}'. Thử provider tiếp theo..."
                    )
                else:
                    print(f"{indent}[-] Provider '{provider_id}' thất bại "
                          f"(HTTP {exec_result['status']}). Thử provider tiếp theo...")

            if not resolved:
                print(f"{'  ' * (recursion_depth + 1)}[!] Không resolve được '{missing_field}' "
                      f"cho '{api_id}' sau khi thử {len(candidates)} provider(s).")

    def get_highest_confidence_edge(self, current_api, next_api):
        edges = self.adjacency_list.get(current_api, [])
        best_edge = None
        for edge in edges:
            if edge['to'] == next_api:
                if not best_edge or edge.get('max_confidence', 0) > best_edge.get('max_confidence', 0):
                    best_edge = edge
        return best_edge

    def calculate_adaptive_bfs_threshold(self):
        # Ép BFS Threshold = 0 để ngay từ Depth 1 trở đi, 
        # BucketManager sẽ gọt số lượng beam xuống beam_width (VD: 3) x 4 buckets = tối đa 12 beams.
        # Điều này giúp ngăn chặn bùng nổ tổ hợp (combinatorial explosion)
        # khiến Fuzzer bị kẹt 4-5 tiếng không bao giờ chạy xong.
        return 0

    def run(self, max_depth=5, initial_state=None):
        if initial_state is None:
            initial_state = StateStore()

        bfs_threshold = self.calculate_adaptive_bfs_threshold()
        print(f"\n[*] Đồ thị có out-degree trung bình. Đặt BFS Threshold = {bfs_threshold}")

        beams = []
        for op in self.operations:
            # DELETE changes shared external state and can invalidate every
            # later workflow (especially DELETE /user/{id}). It is exercised
            # in the isolated deterministic security phase instead.
            if op.get("method", "GET").upper() == "DELETE":
                continue
            if op.get("potentially_destructive"):
                self.memory.record_experiment_stage(
                    op.get("id", "unknown"), "not_tested",
                    "Potentially destructive operation excluded from shared workflow state",
                    count=0, status="NOT_TESTED",
                )
                continue
            if self._has_authenticated_actor(initial_state) and self._is_registration_api(op):
                continue
            beams.append({
                'chain': [op['id']],
                'score': 0,
                'state': initial_state.clone(),
                'vulnerabilities': []
            })

        completed_strategies = []

        for depth in range(1, max_depth + 1):
            print(f"\n=== DEPTH {depth} (Beams: {len(beams)}) ===")
            next_beams = []
            bucket_manager = CoverageBucketManager(top_k=self.beam_width)

            for beam in beams:
                current_api = beam['chain'][-1]
                self.memory.record_visit(current_api)
                visit_count = self.memory.get_visit_count(current_api)

                current_state = beam['state'].clone()
                vulnerabilities = list(beam.get('vulnerabilities', []))

                print(f"[{current_api}] ── Sinh payload và gửi HTTP Request thật...")
                api_node = self.operations_map[current_api]

                # Sibling beams may hold credentials captured before another
                # beam recovered/recreated this actor. Login must bind against
                # the actor registry's latest lifecycle state.
                self._refresh_login_actor_state(api_node, current_state)
                
                edge_deps = []
                if len(beam['chain']) >= 2:
                    prev_api = beam['chain'][-2]
                    best_edge = self.get_highest_confidence_edge(prev_api, current_api)
                    if best_edge:
                        # Chỉ dùng dep primary/secondary để sinh payload; không dùng dep fallback
                        all_deps = best_edge.get('dependencies', [])
                        strong_deps = [d for d in all_deps if d.get('importance', 'primary') != 'fallback']
                        edge_deps = strong_deps if strong_deps else all_deps

                self.resolve_missing_dependencies(api_node, current_state, beam['chain'])

                exec_result = self.executor.execute_request(
                    api_node=api_node,
                    current_state=current_state,
                    edge_deps=edge_deps
                )

                if result_succeeded(exec_result):
                    if self._is_credential_rotation_api(api_node):
                        current_state.freeze_actor_credentials()
                    if (self._is_login_api(api_node)
                            or self._is_credential_rotation_api(api_node)):
                        self._remember_actor_state(current_state)

                status = exec_result["status"]
                
                self.memory.record_request(
                    api_id=current_api,
                    method=api_node.get("method", "GET").upper(),
                    path=exec_result.get("url", api_node.get("path", "/")),
                    status=status,
                    chain=beam['chain'],
                    response_text=exec_result.get("response_text", ""),
                    request_payload=exec_result.get("sent_payload", {}),
                    payload_source=exec_result.get("payload_source", "NONE"),
                    repair_reason=exec_result.get("repair_reason", ""),
                    repair_history=exec_result.get("repair_history", []),
                    sent_headers=exec_result.get("sent_headers", {}),
                    sent_query=exec_result.get("sent_query", {}),
                    sent_cookies=exec_result.get("sent_cookies", {}),
                    actor_id=exec_result.get(
                        "actor_id", current_state.get("actor_id", "default")
                    ),
                    successful=exec_result.get("successful"),
                    outcome_reason=exec_result.get("outcome_reason", ""),
                    auth_recovery=exec_result.get("auth_recovery", {}),
                    auth_context=exec_result.get("auth_context", {}),
                    sent_files=exec_result.get("sent_files", {}),
                    elapsed_ms=exec_result.get("elapsed_ms"),
                )
                
                already_found = self.memory.is_vulnerability_found(current_api, status)

                if exec_result.get('server_error') or exec_result.get('auth_anomaly') or exec_result.get('response_diff'):
                    if not already_found:
                        vuln_type = "Crash/500" if exec_result.get('server_error') else ("Auth Anomaly" if exec_result.get('auth_anomaly') else "Response Mutation")
                        vuln_entry = {
                            "api": current_api,
                            "status": status,
                            "details": exec_result.get("anomaly_details", []),
                            "type": vuln_type
                        }
                        vulnerabilities.append(vuln_entry)
                        self.memory.record_vulnerability(current_api, status)
                        
                        self.memory.record_finding({
                            "api": current_api,
                            "method": api_node.get("method", "GET").upper(),
                            "path": api_node.get("path", "/"),
                            "status": status,
                            "details": exec_result.get("anomaly_details", []),
                            "type": vuln_type,
                            "chain": beam['chain']
                        })

                # Phase 1 never mutates a valid baseline. Security scoring is
                # added only by run_security_phase() after Beam Search ends.
                agent_score_bonus = 0.0

                # Phase 1 only records confirmed baselines. Security mutations
                # are deferred until every actor has finished Beam Search.
                if result_succeeded(exec_result):
                    self._capture_valid_workflow(
                        api_node=api_node,
                        state=current_state,
                        exec_result=exec_result,
                        chain=list(beam["chain"]),
                    )

                if len(beam['chain']) >= 2:
                    prev_api = beam['chain'][-2]
                    is_success = result_succeeded(exec_result)
                    
                    if not is_success and exec_result.get("repair_skipped"):
                        requests = self.memory.endpoint_stats.get(current_api, {}).get("all_requests", [])
                        has_prior_success = any(req.get("successful") is True for req in requests)
                        if has_prior_success:
                            is_success = True
                            
                    self.graph_builder.update_edge_confidence(prev_api, current_api, success=is_success)
                    self.memory.record_edge_feedback(prev_api, current_api, success=is_success)

                base_score = self.scorer.calculate_score(exec_result, depth, visit_count, already_found=already_found)
                current_score = beam['score'] + base_score + agent_score_bonus

                # TÌM CÁC NHÁNH (NEIGHBORS) ĐỂ RẼ NHÁNH CHO DEPTH TIẾP THEO
                # Lấy toàn bộ neighbor kèm edge_type để có thể penalize fallback
                outgoing_edges = self.adjacency_list.get(current_api, [])
                neighbor_edges = [
                    edge for edge in outgoing_edges
                    if edge.get('max_confidence', 0) > 0 and edge['to'] not in beam['chain']
                    and not (
                        self._has_authenticated_actor(current_state)
                        and self._is_registration_api(self.operations_map.get(edge['to'], {}))
                    )
                    and self.operations_map.get(edge['to'], {}).get("method", "GET").upper() != "DELETE"
                    and not self.operations_map.get(edge['to'], {}).get("potentially_destructive")
                ]

                has_valid_branch = False
                if depth < max_depth and neighbor_edges:
                    for edge in neighbor_edges:
                        n         = edge['to']
                        edge_type = edge.get('edge_type', 'strong')
                        has_valid_branch = True
                        new_chain = list(beam['chain'])
                        new_chain.append(n)

                        # Phân tầng điểm theo edge_type:
                        #   strong  → +5  (cạnh đã xác nhận confidence cao)
                        #   medium  →  0  (cạnh bình thường)
                        #   fallback→ -5  (cạnh yếu / safety-net, vẫn thử nhưng ưu tiên thấp)
                        EDGE_SCORE = {'strong': 5, 'medium': 0, 'fallback': -5}
                        edge_score_delta = EDGE_SCORE.get(edge_type, 0)

                        new_beam = {
                            'chain': new_chain,
                            'score': current_score + edge_score_delta,

                            'state': current_state.clone(),
                            'vulnerabilities': list(vulnerabilities)
                        }

                        if depth <= bfs_threshold:
                            if len(next_beams) < 500:
                                next_beams.append(new_beam)
                        else:
                            bucket_manager.add_to_bucket(
                                chain=new_beam['chain'],
                                score=new_beam['score'],
                                state=new_beam['state'],
                                vulnerabilities=new_beam['vulnerabilities']
                            )

                # Nếu là depth cuối, hoặc API này không có ngõ ra nào (đường cụt), ta lưu lại làm chiến thuật hoàn chỉnh.
                if depth == max_depth or not has_valid_branch:
                    strat = {
                        'score': round(current_score, 2),
                        'chain': beam['chain'],
                        'captured_state': {k: str(v) for k, v in current_state.memory.items() if k not in ['password', 'auth_token']},
                        'vulnerabilities': vulnerabilities
                    }
                    completed_strategies.append(strat)
                    self.memory.add_strategy(strat)

            if depth <= bfs_threshold:
                beams = next_beams
            else:
                beams = bucket_manager.get_all_beams()

            if not beams:
                print("Không còn nhánh nào để duyệt.")
                break

        return completed_strategies

    # ── Explicit two-phase pipeline ─────────────────────────────────────────

    @staticmethod
    def _has_authenticated_actor(state: StateStore) -> bool:
        return bool(state.get("auth_token") or state.get("auth_cookies"))

    @staticmethod
    def _is_registration_api(api_node: dict) -> bool:
        text = " ".join((str(api_node.get("id", "")), str(api_node.get("path", ""))))
        return bool(re.search(r"signup|sign[_-]?up|register|registration", text, re.I))

    @staticmethod
    def _is_login_api(api_node: dict) -> bool:
        text = " ".join((str(api_node.get("id", "")), str(api_node.get("path", ""))))
        return bool(re.search(
            r"login|log[_-]?in|signin|sign[_-]?in|authenticate|issue[_-]?token",
            text, re.I,
        ))

    @staticmethod
    def _is_credential_rotation_api(api_node: dict) -> bool:
        if str(api_node.get("method", "GET")).upper() not in {"PUT", "PATCH"}:
            return False
        return any(
            str((meta if isinstance(meta, dict) else {}).get("in", "body")).lower()
            == "body"
            and re.search(
                r"password|passwd|passphrase",
                " ".join((
                    str(field_name),
                    str((meta if isinstance(meta, dict) else {}).get(
                        "original", field_name
                    )),
                )),
                re.I,
            )
            for field_name, meta in (api_node.get("inputs", {}) or {}).items()
        )

    def _refresh_login_actor_state(self, api_node: dict, state: StateStore) -> None:
        if not self._is_login_api(api_node):
            return
        actor = self.actor_contexts.get(state.get("actor_id", "default"))
        if actor is None or not (actor.credentials or actor.auth_token or actor.cookies):
            return
        latest = actor.to_state_store(base={
            "auth_header_name": state.get("auth_header_name", "Authorization"),
            "auth_header_prefix": state.get("auth_header_prefix", "Bearer"),
        })
        if (latest.get_actor_credentials() == state.get_actor_credentials()
                and latest.get("auth_token") == state.get("auth_token")
                and latest.get("auth_cookies") == state.get("auth_cookies")):
            return
        state.replace_auth_context_from(latest)

    def _remember_actor_state(self, state: StateStore) -> None:
        actor = self.actor_contexts.get(state.get("actor_id", "default"))
        if actor is None:
            return
        actor.role = state.get("actor_role") or actor.role
        actor.auth_token = state.get("auth_token", "")
        actor.refresh_token = state.get("refresh_token", "")
        actor.credentials = state.get_actor_credentials()
        actor.cookies = dict(state.get("auth_cookies", {}) or {})
        actor.auth_transports = state.get_auth_transports()

    @staticmethod
    def _is_auth_lifecycle_api(api_node: dict) -> bool:
        text = " ".join((
            str(api_node.get("id", "")),
            str(api_node.get("path", "")),
        ))
        return bool(re.search(
            r"login|signin|signup|register|logout|refresh|forgot|reset|otp|captcha",
            text,
            re.I,
        ))

    def _capture_valid_workflow(self, api_node: dict, state: StateStore,
                                exec_result: dict, chain: list) -> None:
        """Persist a replayable in-memory baseline after semantic success."""
        api_id = api_node.get("id", "unknown")
        actor_id = state.get("actor_id", "default")
        key = (actor_id, api_id)
        # Freeze the endpoint's own baseline before cloning the replay case.
        # Cloning first leaves every stored case without its current endpoint
        # response, so the authorization auditor has nothing to compare with.
        state.set_baseline(api_id, exec_result)
        candidate = {
            "api_node": dict(api_node),
            "state": state.clone(),
            "exec_result": dict(exec_result),
            "chain": list(chain),
        }
        existing = self._valid_workflows.get(key)
        if existing is None or len(chain) < len(existing["chain"]):
            self._valid_workflows[key] = candidate

        self.attack_store.observe_operation(
            api_node,
            request_values=exec_result.get("sent_payload", {}),
            response_value=exec_result.get("raw_response"),
            actor_id=str(actor_id),
            successful=True,
        )

        if api_node.get("method", "GET").upper() == "DELETE":
            for deleted in exec_result.get("deleted_references", []) or []:
                self.attack_store.invalidate(
                    resource_type=deleted.get("resource_type", ""),
                    selector_field=deleted.get("selector_field", ""),
                    resource_id=deleted.get("resource_id"),
                    owner_actor_id=actor_id,
                )
            return
        self._record_response_resources(api_node, state, exec_result)

    @staticmethod
    def _declared_selector_meta(operation, selector, resource_type):
        canonical = AttackStore.normalize_selector(selector, resource_type)
        for field, raw_meta in (operation.get("outputs", {}) or {}).items():
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            if meta.get("_passthrough"):
                continue
            names = (field, meta.get("original", ""), meta.get("contextual_name", ""))
            if any(
                AttackStore.normalize_selector(name, resource_type) == canonical
                for name in names if name
            ):
                return meta
        return None

    @staticmethod
    def _value_at_json_path(value, json_path):
        parts = [part for part in re.split(r"\.|\[\]", str(json_path or "")) if part]
        if not parts:
            return None

        def _walk(current, remaining):
            if not remaining:
                return current
            if isinstance(current, list):
                values = [_walk(item, remaining) for item in current]
                return next((item for item in values if item not in (None, "")), None)
            if not isinstance(current, dict) or remaining[0] not in current:
                return None
            return _walk(current[remaining[0]], remaining[1:])

        found = _walk(value, parts)
        if found in (None, "") and len(parts) > 1:
            # extract_props prefixes referenced schemas with their component
            # name, while wire responses commonly omit that wrapper.
            found = _walk(value, parts[1:])
        return found

    def _record_response_resources(self, api_node, state, exec_result):
        """Record selectors proven by a successful create post-condition."""
        if str(api_node.get("method", "GET")).upper() != "POST":
            return 0
        raw_response = exec_result.get("raw_response")
        if exec_result.get("schema_valid") is False or not result_succeeded(exec_result):
            return 0
        experiments = [
            item for item in self.authorization_experiments
            if item.producer_api == api_node.get("id")
        ]
        recorded = 0
        for experiment in experiments:
            meta = self._declared_selector_meta(
                api_node, experiment.selector_field, experiment.resource_type
            )
            if not meta or not meta.get("json_path"):
                continue
            request_postcondition = bool(meta.get("_request_passthrough"))
            source = exec_result.get("sent_payload", {}) if request_postcondition else raw_response
            resource_id = self._value_at_json_path(source, meta["json_path"])
            if resource_id in (None, "") or isinstance(resource_id, (dict, list)):
                continue
            owner_context = {
                "actor_id": state.get("actor_id", "default"),
                "user_id": state.get("user_id") or state.get("id"),
                "email": state.get("email"),
            }
            provenance = "CREATED_REQUEST" if request_postcondition else "CREATED_RESPONSE"
            chain = ProvenanceChain.single(
                "create_request_postcondition" if request_postcondition else "create_response",
                ProvenanceLevel.AUTHORITATIVE, 0.95,
                relation=experiment.resource_type,
                actor_id=str(owner_context["actor_id"]),
                operation_id=str(api_node.get("id", "unknown")),
            )
            self.attack_store.record(
                api_node.get("id", "unknown"), experiment.selector_field, resource_id,
                endpoint=exec_result.get("url", api_node.get("path", "")),
                user_context={k: v for k, v in owner_context.items() if v},
                owner_actor_id=owner_context["actor_id"], confidence=0.9,
                resource_type=experiment.resource_type,
                owner_role=state.get("actor_role", ""),
                provenance=provenance, provenance_chain=chain,
                producer_method="POST", schema=meta,
            )
            recorded += 1
        return recorded

    def run_security_phase(self) -> dict:
        """Phase 2: test only endpoints that Phase 1 proved replayable.

        This method never participates in Beam Search. It consumes frozen
        baseline state, executes security variants, and records findings.
        """
        summary = {
            "baselines": len(self._valid_workflows),
            "tested_endpoints": 0,
            "skipped_auth_lifecycle": 0,
            "baseline_replay_failures": 0,
            "errors": 0,
            "suspected": 0,
            "unverified": 0,
        }
        observation_start = len(self.memory.security_observations)
        if not self.enable_security_testing:
            log.info("[Phase 2] Security testing disabled")
            return summary
        if not self._attacker or not self._auditor:
            log.warning("[Phase 2] Attacker/Auditor unavailable")
            return summary

        self._pipeline_phase = "security"
        print(
            f"\n=== PHASE 2: SECURITY VALIDATION "
            f"({len(self._valid_workflows)} valid actor-endpoint baselines) ==="
        )
        try:
            ordered_cases = sorted(
                self._valid_workflows.values(),
                key=lambda case: (len(case["chain"]), case["api_node"].get("id", "")),
            )
            for case in ordered_cases:
                api_node = case["api_node"]
                api_id = api_node.get("id", "unknown")
                state = case["state"].clone()
                baseline = dict(case["exec_result"])
                chain = list(case["chain"])

                exposure = self._auditor.audit_baseline_exposure(
                    baseline, state, api_node
                )
                if exposure.classification == "CONFIRMED" and exposure.finding:
                    status = int(baseline.get("status", 0) or 0)
                    already_recorded = any(
                        finding.get("api") == api_id
                        and finding.get("type") == "EXCESSIVE_DATA_EXPOSURE"
                        for finding in self.memory.findings
                    )
                    if not already_recorded:
                        finding = dict(exposure.finding)
                        finding["chain"] = chain
                        self.memory.record_finding(finding)
                        self.memory.record_vulnerability(api_id, status)
                        self.memory.record_experiment_stage(
                            api_id, "confirmed", exposure.reasoning,
                            status="CONFIRMED",
                        )
                elif exposure.classification == "SUSPECTED":
                    self.memory.record_security_observation({
                        "classification": "SUSPECTED",
                        "type": exposure.bola_type,
                        "api": api_id,
                        "method": api_node.get("method", "GET").upper(),
                        "path": api_node.get("path", ""),
                        "confidence": exposure.confidence,
                        "evidence": exposure.evidence,
                        "reasoning": exposure.reasoning,
                    })

                if self._is_auth_lifecycle_api(api_node):
                    summary["skipped_auth_lifecycle"] += 1
                    continue

                vulnerabilities = []
                print(
                    f"[Phase 2] Testing api={api_id} "
                    f"actor={state.get('actor_id', 'default')}"
                )
                try:
                    if api_node.get("method", "GET").upper() == "DELETE":
                        prepared = self._prepare_destructive_authorization_case(
                            api_node, state
                        )
                        if prepared is None:
                            reason = self._last_provisioning_failure or "Resource provisioning failed"
                            self.memory.record_experiment_stage(
                                api_id, "provisioning_failed", reason, count=0,
                                status="provisioning_failed",
                            )
                            self.memory.record_security_observation({
                                "classification": "NOT_TESTED", "type": "BOLA",
                                "api": api_id,
                                "reason_code": "provisioning_failed",
                                "reasoning": reason,
                            })
                            continue
                        self._run_3agent_pipeline(
                            api_node=api_node, current_state=state,
                            exec_result=prepared, beam_chain=chain,
                            vulnerabilities=vulnerabilities,
                        )
                        summary["tested_endpoints"] += 1
                        continue

                    # Revalidate the frozen case against current target state.
                    # This catches expired tokens/deleted resources before any
                    # mutation is generated.
                    replay = self.executor.execute_request(
                        api_node=api_node,
                        current_state=state,
                        payload_override=baseline.get("sent_payload", {}),
                        payload_source_override="BASELINE_REPLAY",
                        allow_repair=True,
                        allow_auth_recovery=True,
                    )
                    self.memory.record_request(
                        api_id=api_id,
                        method=api_node.get("method", "GET").upper(),
                        path=replay.get("url", api_node.get("path", "/")),
                        status=replay.get("status", 0),
                        chain=chain,
                        response_text=replay.get("response_text", ""),
                        request_payload=replay.get("sent_payload", {}),
                        payload_source="BASELINE_REPLAY",
                        repair_reason=replay.get("repair_reason", ""),
                        repair_history=replay.get("repair_history", []),
                        sent_headers=replay.get("sent_headers", {}),
                        sent_query=replay.get("sent_query", {}),
                        sent_cookies=replay.get("sent_cookies", {}),
                        actor_id=replay.get("actor_id", state.get("actor_id", "default")),
                        successful=replay.get("successful"),
                        outcome_reason=replay.get("outcome_reason", ""),
                        auth_recovery=replay.get("auth_recovery", {}),
                        auth_context=replay.get("auth_context", {}),
                        sent_files=replay.get("sent_files", {}),
                        elapsed_ms=replay.get("elapsed_ms"),
                    )
                    if not result_succeeded(replay):
                        summary["baseline_replay_failures"] += 1
                        log.warning(
                            f"[Phase 2] Skip {api_id}: baseline replay failed "
                            f"HTTP {replay.get('status')} {replay.get('outcome_reason', '')}"
                        )
                        self.memory.record_security_observation({
                            "classification": "NOT_TESTED",
                            "type": "BOLA",
                            "api": api_id,
                            "reason_code": "baseline_replay_failed",
                            "reasoning": (
                                f"Frozen baseline could not be replayed: HTTP "
                                f"{replay.get('status', 0)} {replay.get('outcome_reason', '')}"
                            ).strip(),
                        })
                        continue
                    baseline = replay

                    self._run_local_mutator_security_case(
                        api_node, state, baseline, chain, vulnerabilities
                    )
                    self._run_3agent_pipeline(
                        api_node=api_node,
                        current_state=state,
                        exec_result=baseline,
                        beam_chain=chain,
                        vulnerabilities=vulnerabilities,
                    )
                    summary["tested_endpoints"] += 1
                except Exception as exc:
                    summary["errors"] += 1
                    log.exception(f"[Phase 2] Failed security case {api_id}: {exc}")

            self._run_registration_mass_assignment_cases(summary)

            # Destructive endpoints are intentionally absent from Phase 1.
            # Run them last with a freshly-created resource so they cannot
            # poison unrelated baselines or invalidate actor sessions early.
            for experiment in self.authorization_experiments:
                if experiment.operation != "DELETE":
                    continue
                owner_state = self._authorization_owner_state()
                if owner_state is None:
                    self.memory.record_security_observation({
                        "classification": "NOT_TESTED", "type": "BOLA",
                        "api": experiment.target_api,
                        "reasoning": "No authenticated same-role owner/attacker pair",
                    })
                    continue
                target = self.operations_map[experiment.target_api]
                prepared = self._prepare_destructive_authorization_case(
                    target, owner_state
                )
                if prepared is None:
                    reason = self._last_provisioning_failure or "Resource provisioning failed"
                    self.memory.record_experiment_stage(
                        experiment.target_api, "provisioning_failed", reason,
                        count=0, status="provisioning_failed",
                    )
                    self.memory.record_security_observation({
                        "classification": "NOT_TESTED", "type": "BOLA",
                        "api": experiment.target_api,
                        "reason_code": "provisioning_failed",
                        "reasoning": reason,
                    })
                    continue
                self._run_3agent_pipeline(
                    api_node=target, current_state=owner_state,
                    exec_result=prepared, beam_chain=[
                        experiment.producer_api, experiment.target_api,
                        experiment.verifier_api,
                    ], vulnerabilities=[],
                )
                summary["tested_endpoints"] += 1
        finally:
            self._pipeline_phase = "complete"
            observations = self.memory.security_observations[observation_start:]
            summary["suspected"] = sum(
                item.get("classification") == "SUSPECTED" for item in observations
            )
            summary["unverified"] = sum(
                item.get("classification") == "UNVERIFIED" for item in observations
            )

        print(
            "[Phase 2] Complete: "
            f"tested={summary['tested_endpoints']}, "
            f"replay_failed={summary['baseline_replay_failures']}, "
            f"skipped_auth={summary['skipped_auth_lifecycle']}, "
            f"errors={summary['errors']}"
        )
        return summary

    def _authorization_owner_state(self):
        for actor in self.actor_contexts.all():
            if actor.role == "anonymous" or (not actor.auth_token and not actor.cookies):
                continue
            owner = actor.to_state_store()
            if self._select_attack_state(owner) is not None:
                return owner
        return None

    def _prepare_destructive_authorization_case(self, target_node, owner_state):
        """Create R1 without consuming it through the owner's DELETE baseline."""
        provisioned = self.resource_provisioner.provision(target_node, owner_state)
        if not provisioned.succeeded:
            self._last_provisioning_failure = provisioned.reason
            return None
        self._last_provisioning_failure = ""
        prepared = dict(provisioned.create_result)
        prepared["sent_payload"] = {
            **dict(provisioned.create_result.get("sent_payload", {})),
            provisioned.selector_field: provisioned.resource_id,
        }
        return prepared

    def get_valid_workflow_count(self) -> int:
        return len(self._valid_workflows)

    def seed_actor_identity_resources(self, producer_api: str = "") -> int:
        """Treat successfully bootstrapped principals as created user resources."""
        recorded = 0
        for actor in self.actor_contexts.all():
            if actor.role == "anonymous":
                continue
            user_id = actor.credentials.get("user_id") or actor.credentials.get("id")
            if user_id in (None, ""):
                continue
            self.attack_store.record(
                producer_api or "ACTOR_BOOTSTRAP", "id", user_id,
                owner_actor_id=actor.actor_id, owner_role=actor.role,
                resource_type="user", provenance="CREATED_RESPONSE",
                producer_method="POST",
                user_context={"actor_id": actor.actor_id, "user_id": user_id},
            )
            actor.remember_resource("user", user_id)
            recorded += 1
        return recorded

    def _run_local_mutator_security_case(self, api_node: dict, state: StateStore,
                                         baseline: dict, chain: list,
                                         vulnerabilities: list) -> None:
        method = str(api_node.get("method", "GET")).upper()
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return
        valid_payload = baseline.get("sent_payload", {})
        if not valid_payload:
            return
        api_id = api_node.get("id", "unknown")
        blast_results = asyncio.run(AsyncFuzzEngine.blast_api(
            url=baseline.get("url"),
            method=method,
            headers=baseline.get("sent_headers", {}),
            query=baseline.get("sent_query", {}),
            cookies=baseline.get("sent_cookies", {}),
            valid_payload=valid_payload,
            num_requests=50,
        ))
        for result in blast_results:
            status = result.get("status", 0)
            self.memory.record_request(
                api_id=api_id,
                method=method,
                path=baseline.get("url", api_node.get("path", "/")),
                status=status,
                chain=chain,
                response_text=result.get("text", result.get("error", "")),
                request_payload=result.get("payload", {}),
                payload_source="LOCAL_MUTATOR",
                sent_headers=baseline.get("sent_headers", {}),
                sent_query=baseline.get("sent_query", {}),
                sent_cookies=baseline.get("sent_cookies", {}),
                actor_id=state.get("actor_id", "default"),
                auth_context=baseline.get("auth_context", state.get_auth_context()),
                elapsed_ms=result.get("elapsed_ms"),
                transport_attempted=result.get("transport_attempted"),
            )
            if status >= 500 and not self.memory.is_vulnerability_found(api_id, status):
                finding = {
                    "api": api_id,
                    "method": method,
                    "path": baseline.get("url", api_node.get("path", "/")),
                    "status": status,
                    "details": ["Gây ra lỗi 500 bằng Local Mutator sau valid baseline"],
                    "type": "Crash/500",
                    "chain": chain,
                }
                vulnerabilities.append(finding)
                self.memory.record_vulnerability(api_id, status)
                self.memory.record_finding(finding)

    # ── 3-Agent Pipeline ──────────────────────────────────────────────────────

    def _run_3agent_pipeline(
        self,
        api_node:       dict,
        current_state:  "StateStore",
        exec_result:    dict,
        beam_chain:     list,
        vulnerabilities: list,
    ) -> float:
        """
        Chạy pipeline 3-agent sau khi request hợp lệ thành công (2xx):

          1. Lưu baseline vào StateStore (step 16 chuẩn bị)
          2. Harvest resource IDs vào AttackStore (chuẩn bị Reference Forge)
          3. [Attacker Agent] Sinh attack variants (ID Sub / Param Pollute / Ref Forge)
          4. Thực thi các attack variants qua RequestExecutor
          5. [Auditor Agent] Phân tích response → BOLA?
          6. Nếu BOLA → ghi finding, cộng score bonus

        Returns:
            float: Tổng score bonus cộng thêm vào beam score
        """
        api_id       = api_node.get("id", "unknown")
        total_bonus  = 0.0

        # ── Bước 1: Lưu baseline ──────────────────────────────────────────────
        current_state.set_baseline(api_id, exec_result)

        # ── Bước 2: Harvest IDs vào AttackStore ───────────────────────────────
        n_harvested = self._record_response_resources(api_node, current_state, exec_result)
        if n_harvested:
            log.info(f"[AttackStore] Harvested {n_harvested} schema-backed IDs from {api_id}")

        # Prefer a distinct principal for authorization tests. The owner state
        # remains the baseline; the selected state supplies the attack token.
        attack_state = self._select_attack_state(current_state)
        if attack_state is None:
            self.memory.record_security_observation({
                "classification": "NOT_TESTED", "type": "BOLA", "api": api_id,
                "owner_actor_id": current_state.get("actor_id", "default"),
                "owner_role": current_state.get("actor_role", ""),
                "reasoning": (
                    "No compatible distinct authenticated principal; explicit roles "
                    "must match when the dataset declares them"
                ),
            })
            return 0.0
        preflight_ok, preflight_reason = self._preflight_actor(attack_state)
        if not preflight_ok:
            self.memory.record_security_observation({
                "classification": "INFRA_FAILURE", "type": "BOLA", "api": api_id,
                "attacker_actor_id": attack_state.get("actor_id", "default"),
                "reasoning": preflight_reason,
            })
            return 0.0

        # ── Bước 3: Attacker Agent sinh variants ──────────────────────────────
        valid_payload = exec_result.get("sent_payload", {})
        valid_response = exec_result.get("raw_response")
        try:
            attack_variants = self._attacker.generate_attacks(
                api_node=api_node,
                state=attack_state,
                valid_payload=valid_payload,
                valid_response=valid_response,
            )
        except Exception as e:
            log.exception(f"[AttackerAgent] Error generating attacks for {api_id}: {e}")
            self.memory.record_experiment_stage(
                api_id, "generation_failed", f"{type(e).__name__}: {e}", count=0,
                status="generation_failed",
            )
            self.memory.record_security_observation({
                "classification": "INFRA_FAILURE",
                "type": "BOLA",
                "api": api_id,
                "owner_actor_id": current_state.get("actor_id", "default"),
                "attacker_actor_id": attack_state.get("actor_id", "default"),
                "reasoning": (
                    f"Attack generation failed: {type(e).__name__}: {e}"
                ),
            })
            return 0.0

        if not attack_variants:
            log.info(f"[AttackerAgent] No attack variants generated for {api_id}")
            errors = list(getattr(self._attacker, "generation_errors", []) or [])
            reason = (
                "; ".join(item.get("reason", "") for item in errors)
                or "No schema-compatible alternative observed during this run"
            )
            self.memory.record_experiment_stage(
                api_id,
                "generation_failed" if errors else "not_tested",
                reason,
                count=0,
                status="generation_failed" if errors else "NOT_TESTED",
            )
            if errors:
                self.memory.record_security_observation({
                    "classification": "NOT_TESTED", "type": "BOLA", "api": api_id,
                    "reason_code": "generation_failed",
                    "reasoning": reason,
                })
            return 0.0

        self.memory.record_experiment_stage(
            api_id, "generated", "Reference/mutation variants generated",
            count=len(attack_variants),
        )

        # Deterministic/replayable cases always run before random and LLM fuzzing.
        attack_variants.sort(
            key=lambda item: 0 if item.extra.get("confirmation_eligible") else 1
        )

        log.info(f"\033[95m[3-Agent]\033[0m Running {len(attack_variants)} attack variants on {api_id}")

        # ── Bước 4 & 5: Thực thi variants + Audit ────────────────────────────
        baseline_response = current_state.get_baseline(api_id)

        for variant in attack_variants:
            # Compatibility for variants created before the canonical identity
            # fields were introduced, and for third-party attack generators.
            variant.extra.setdefault(
                "resource_id", variant.extra.get("substitute_id")
            )
            variant.extra.setdefault(
                "selector_field",
                variant.extra.get("field") or variant.extra.get("field_path", ""),
            )
            variant.extra.setdefault(
                "resource_type",
                api_node.get("resource_type")
                or api_node.get("path")
                or api_node.get("id", ""),
            )
            variant_owner_id = (
                variant.extra.get("owner_actor_id")
                or current_state.get("actor_id", "default")
            )
            baseline_owner_id = current_state.get("actor_id", "default")
            owner_role = variant.extra.get("owner_role", "")
            actor_relationship = variant.extra.get("actor_relationship", "")
            if variant_owner_id == baseline_owner_id:
                owner_role = owner_role or current_state.get("actor_role", "")
                actor_relationship = actor_relationship or attack_state.get(
                    "actor_relationship", ""
                )
            # Tạo modified api_node với path đã bị biến đổi
            attack_node = dict(variant.api_node)
            attack_node["path"] = variant.path

            try:
                operation = attack_node.get("method", "GET").upper()
                if operation in ("POST", "PUT", "PATCH"):
                    baseline_payload = exec_result.get("sent_payload", {}) or {}
                    if (variant.payload == baseline_payload
                            and not variant.extra.get("confirmation_eligible")):
                        try:
                            variant.payload, mutation = ObservableMutator.mutate_request(
                                attack_node,
                                variant.payload,
                                excluded_paths=(
                                    variant.extra.get("field_path", ""),
                                    variant.extra.get("field", ""),
                                ),
                            )
                            variant.extra["observable_mutation"] = mutation
                        except ValueError as exc:
                            reason = f"No observable schema-valid mutation: {exc}"
                            self.memory.record_experiment_stage(
                                api_id, "generation_failed", reason, count=0,
                                status="generation_failed",
                            )
                            self.memory.record_security_observation({
                                "classification": "NOT_TESTED", "type": "BOLA",
                                "api": api_id, "reason_code": "generation_failed",
                                "reasoning": reason,
                            })
                            continue
                    else:
                        variant.extra.setdefault("observable_mutation", {
                            "location": variant.extra.get("location", "body"),
                            "field_path": variant.extra.get("field_path", variant.extra.get("field", "")),
                            "before": variant.extra.get("original_id"),
                            "after": variant.extra.get("substitute_id", variant.extra.get("resource_id")),
                        })
                pre_attack_owner_response = None
                if (variant.extra.get("confirmation_eligible")
                        and operation in ("PATCH", "PUT")):
                    candidate = self._execute_owner_verifier(
                        variant, current_state, "BOLA_OWNER_PRECHECK"
                    )
                    if (candidate is not None and result_succeeded(candidate)
                            and candidate.get("schema_valid") is not False
                            and self._response_has_fingerprint(
                                candidate,
                                variant.extra.get("resource_id"),
                                variant.extra.get("marker"),
                                variant.extra.get("selector_field"),
                                variant.extra.get("resource_type", ""),
                            )):
                        pre_attack_owner_response = candidate

                # Thực thi attack request
                attack_exec = self.executor.execute_request(
                    api_node=attack_node,
                    current_state=attack_state,
                    edge_deps=None,
                    payload_override=variant.payload,
                    payload_source_override=f"ATTACKER_{variant.strategy.upper()}",
                    # A 401/403 is an expected authorization outcome. Repairing
                    # an attack may also undo its security mutation.
                    allow_repair=False,
                )
                self.memory.record_experiment_stage(
                    api_id, "executed", f"HTTP {attack_exec.get('status', 0)}",
                    status="executed",
                )

                reproduction_count = 1
                fingerprint_verified = self._response_has_fingerprint(
                    attack_exec, variant.extra.get("resource_id"), variant.extra.get("marker"),
                    variant.extra.get("selector_field"), variant.extra.get("resource_type", ""),
                )
                if (variant.extra.get("confirmation_eligible")
                        and operation == "GET" and fingerprint_verified):
                    replay_exec = self.executor.execute_request(
                        api_node=attack_node,
                        current_state=attack_state,
                        edge_deps=None,
                        payload_override=variant.payload,
                        payload_source_override="DETERMINISTIC_BOLA_REPLAY",
                        allow_repair=False,
                    )
                    if self._response_has_fingerprint(
                            replay_exec, variant.extra.get("resource_id"), variant.extra.get("marker"),
                            variant.extra.get("selector_field"), variant.extra.get("resource_type", "")) \
                            :
                        reproduction_count = 2
                mutation_verified = False
                if operation in ("PATCH", "PUT", "DELETE") and result_succeeded(attack_exec):
                    mutation_verified = self._verify_owner_state_after_attack(
                        variant, current_state, operation,
                        pre_attack_response=pre_attack_owner_response,
                    )
                    # A destructive/mutating replay must use a newly-created
                    # resource. Reusing the first ID makes DELETE inherently
                    # non-reproducible and makes PATCH susceptible to idempotency.
                    if mutation_verified:
                        reproduced = self._reproduce_mutation_with_fresh_resource(
                            api_node, variant, current_state, attack_state, operation)
                        if reproduced:
                            reproduction_count = 2

                # Ghi lại attack request vào memory
                self.memory.record_request(
                    api_id=api_id,
                    method=attack_node.get("method", "GET").upper(),
                    path=attack_exec.get("url", variant.path),
                    status=attack_exec["status"],
                    chain=beam_chain,
                    response_text=attack_exec.get("response_text", ""),
                    request_payload=attack_exec.get("sent_payload", variant.payload),
                    payload_source=f"ATTACKER_{variant.strategy.upper()}",
                    sent_headers=attack_exec.get("sent_headers", {}),
                    sent_query=attack_exec.get("sent_query", {}),
                    sent_cookies=attack_exec.get("sent_cookies", {}),
                    sent_files=attack_exec.get("sent_files", {}),
                    actor_id=attack_exec.get(
                        "actor_id", attack_state.get("actor_id", "default")
                    ),
                    attack_metadata={
                        "strategy": variant.strategy,
                        "technique": variant.extra.get("technique", variant.strategy),
                        "description": variant.description,
                        "owner_actor_id": variant_owner_id,
                        "attacker_actor_id": attack_state.get("actor_id", "default"),
                        "baseline": {
                            "path": exec_result.get("url", api_node.get("path", "")),
                            "body": exec_result.get("sent_payload", {}),
                            "query": exec_result.get("sent_query", {}),
                        },
                        "attack": {
                            "path": attack_exec.get("url", variant.path),
                            "body": attack_exec.get("sent_payload", variant.payload),
                            "query": attack_exec.get("sent_query", {}),
                        },
                        "mutation": dict(variant.extra),
                    },
                    auth_recovery=attack_exec.get("auth_recovery", {}),
                    elapsed_ms=attack_exec.get("elapsed_ms"),
                    auth_context=attack_exec.get("auth_context", {}),
                )

                # ── Auditor Agent: phân tích response ─────────────────────────
                variant_info = {
                    "strategy":    variant.strategy,
                    "description": variant.description,
                    "extra":       {
                        **variant.extra,
                        "attacker_actor_id": attack_state.get("actor_id", "default"),
                        "owner_actor_id": variant_owner_id,
                        "attacker_role": attack_state.get("actor_role", ""),
                        "owner_role": owner_role,
                        "actor_relationship": actor_relationship,
                        "preflight_ok": True,
                        "preflight_reason": preflight_reason,
                        "operation": attack_node.get("method", "GET").upper(),
                        "reproduction_count": reproduction_count,
                        "fingerprint_verified": fingerprint_verified and reproduction_count == 2,
                        "mutation_verified": mutation_verified,
                    },
                }

                audit_result = self._auditor.audit(
                    attack_variant_info=variant_info,
                    attack_response=attack_exec,
                    baseline_response=baseline_response,
                    state=attack_state,
                    api_node=api_node,
                )
                if audit_result.classification not in ("NOT_TESTED", "INFRA_FAILURE"):
                    self.memory.record_experiment_stage(
                        api_id, "verifiable", audit_result.reasoning,
                        status=audit_result.classification,
                    )

                if audit_result.classification in ("SUSPECTED", "UNVERIFIED"):
                    observation_class = audit_result.classification
                    self.memory.record_security_observation({
                        "classification": observation_class,
                        "type": audit_result.bola_type or "BROKEN_ACCESS_CONTROL",
                        "api": api_id,
                        "method": attack_node.get("method", "GET").upper(),
                        "path": attack_exec.get("url", variant.path),
                        "strategy": variant.strategy,
                        "owner_actor_id": variant_owner_id,
                        "attacker_actor_id": attack_state.get("actor_id", "default"),
                        "confidence": audit_result.confidence,
                        "evidence": audit_result.evidence,
                        "reasoning": audit_result.reasoning,
                        "chain": list(beam_chain),
                    })

                log.info(
                    f"[AuditorAgent] {variant.strategy}: "
                    f"bola={audit_result.is_bola} conf={audit_result.confidence:.2f}"
                )

                # ── Step 18: Tăng điểm nếu BOLA ───────────────────────────────
                if audit_result.is_bola:
                    self.memory.record_experiment_stage(
                        api_id, "confirmed", audit_result.reasoning,
                        status="CONFIRMED",
                    )
                    total_bonus += audit_result.score_delta

                    # Ghi Finding vào KnowledgeMemory (step 20)
                    if audit_result.finding:
                        finding = dict(audit_result.finding)
                        finding["chain"] = list(beam_chain)
                        finding["owner_actor_id"] = current_state.get("actor_id", "default")
                        finding["attacker_actor_id"] = attack_state.get("actor_id", "default")
                        finding["baseline"] = {
                            "status": baseline_response.get("status") if baseline_response else None,
                            "url": baseline_response.get("url") if baseline_response else None,
                            "response": baseline_response.get("raw_response") if baseline_response else None,
                        }
                        finding["attack"] = {
                            "status": attack_exec.get("status"),
                            "url": attack_exec.get("url"),
                            "payload": attack_exec.get("sent_payload", {}),
                            "query": attack_exec.get("sent_query", {}),
                            "response": attack_exec.get("raw_response"),
                        }
                        self.memory.record_finding(finding)
                        self.memory.record_replay_recipe({
                            "endpoint_relationship": {
                                "create": variant.extra.get("producer_api", ""),
                                "target": api_id,
                                "verify": api_id,
                            },
                            "resource_type": variant.extra.get("resource_type", ""),
                            "selector_field": variant.extra.get("selector_field", ""),
                            "operation": attack_node.get("method", "GET").upper(),
                            "actor_relationship": variant_info["extra"].get(
                                "actor_relationship", "distinct_authenticated_principals"
                            ),
                        })
                        self.memory.record_vulnerability(api_id, attack_exec["status"])

                        vulnerabilities.append({
                            "api":     api_id,
                            "status":  attack_exec["status"],
                            "details": audit_result.evidence,
                            "type":    f"BOLA/{audit_result.bola_type.upper()}",
                            "strategy": variant.strategy,
                        })

                        print(
                            f"\033[91m[!!!] BOLA FOUND\033[0m api={api_id} "
                            f"strategy={variant.strategy} conf={audit_result.confidence:.2f} "
                            f"score+={audit_result.score_delta:.0f}"
                        )

                # Ghi finding phụ nếu Auditor phát hiện crash từ attack
                elif audit_result.finding and audit_result.finding.get("type", "").startswith("Crash"):
                    finding = dict(audit_result.finding)
                    finding["chain"] = list(beam_chain)
                    self.memory.record_finding(finding)

            except Exception as e:
                log.exception(f"[3-Agent] Error running variant {variant.strategy} on {api_id}: {e}")
                self.memory.record_experiment_stage(
                    api_id, "execution_error", f"{type(e).__name__}: {e}",
                    count=0, status="execution_error",
                )
                self.memory.record_security_observation({
                    "classification": "INCONCLUSIVE", "type": "BOLA",
                    "api": api_id, "reason_code": "execution_error",
                    "reasoning": f"{type(e).__name__}: {e}",
                })
                continue

        return total_bonus

    def _select_attack_state(self, owner_state):
        owner_actor_id = owner_state.get("actor_id", "default")
        owner_role = str(owner_state.get("actor_role", "")).strip().casefold()
        unknown_roles = {"", "unknown", "anonymous", "none", "null"}
        fallback = None
        for actor in self.actor_contexts.all():
            if actor.actor_id == owner_actor_id:
                continue
            if not (actor.auth_token or actor.cookies or actor.auth_transports):
                continue
            base = {
                "auth_header_name": owner_state.get("auth_header_name", "Authorization"),
                "auth_header_prefix": owner_state.get("auth_header_prefix", "Bearer"),
            }
            actor_role = str(actor.role or "").strip().casefold()
            candidate = actor.to_state_store(base=base)
            if owner_role not in unknown_roles and actor_role == owner_role:
                candidate.update(
                    "actor_relationship", "same_role_distinct_principals"
                )
                return candidate
            if owner_role in unknown_roles and actor_role in unknown_roles and fallback is None:
                candidate.update(
                    "actor_relationship", "distinct_authenticated_principals"
                )
                fallback = candidate
        return fallback

    def _preflight_actor(self, state):
        bootstrapper = ActorBootstrapper(self.operations, self.executor)
        verified, reason = bootstrapper.validate_actor(state)
        if verified is True:
            return True, reason
        recovered, recovery_reason = bootstrapper.recover_actor(state)
        if not recovered:
            return False, f"{reason}; recovery failed: {recovery_reason}"
        verified, reason = bootstrapper.validate_actor(state)
        return (verified is True), reason

    @staticmethod
    def _iter_scalar_items(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    yield from TestStrategyEngine._iter_scalar_items(child)
                else:
                    yield key, child
        elif isinstance(value, list):
            for child in value:
                yield from TestStrategyEngine._iter_scalar_items(child)

    @staticmethod
    def _exact_value(left, right):
        return type(left) is type(right) and left == right

    @staticmethod
    def _response_has_fingerprint(result, resource_id, marker="",
                                  selector_field="", resource_type=""):
        if not result_succeeded(result):
            return False
        if result.get("schema_valid") is False:
            return False
        content_type = str(result.get("response_content_type", "")).casefold()
        if "text/html" in content_type:
            return False
        items = list(TestStrategyEngine._iter_scalar_items(result.get("raw_response")))
        if selector_field and resource_id not in (None, ""):
            canonical = AttackStore.normalize_selector(selector_field, resource_type)
            if any(
                AttackStore.normalize_selector(key, resource_type) == canonical
                and TestStrategyEngine._exact_value(value, resource_id)
                for key, value in items
            ):
                return True
        if marker not in (None, ""):
            return any(TestStrategyEngine._exact_value(value, marker) for _key, value in items)
        return False

    def _execute_owner_verifier(self, variant, owner_state, payload_source):
        """Read the variant's exact resource through its OpenAPI verifier."""
        resource_id = variant.extra.get("resource_id")
        experiment = self.authorization_planner.for_target(
            variant.api_node.get("id", "")
        )
        if experiment is None or not self.authorization_planner.validate(experiment) \
                or resource_id in (None, ""):
            return None
        verifier = dict(self.operations_map[experiment.verifier_api])
        verifier["path"] = re.sub(
            r"\{" + re.escape(experiment.selector_field) + r"\}",
            str(resource_id), str(verifier.get("path", "")),
        )
        return self.executor.execute_request(
            verifier, owner_state, payload_source_override=payload_source,
            allow_repair=False,
        )

    def _verify_owner_state_after_attack(
            self, variant, owner_state, operation, pre_attack_response=None):
        """Read the exact resource as its owner after a cross-actor mutation."""
        resource_type = variant.extra.get("resource_type", "")
        selector = variant.extra.get("selector_field") or variant.extra.get("field", "")
        if self._is_credential_rotation_api(variant.api_node):
            return self._verify_password_login(
                variant.extra.get("resource_id"), variant.payload,
                owner_state.get("actor_id", "password_owner"),
            )
        result = self._execute_owner_verifier(
            variant, owner_state, "BOLA_OWNER_VERIFY"
        )
        if result is None:
            return False
        if operation == "DELETE":
            # Deleting an identity can invalidate the victim's own session.
            # A distinct same-role authenticated observer may verify absence;
            # its 404/410 is state evidence, while 401/403 remains inconclusive.
            if int(result.get("status", 0) or 0) in (401, 403) or \
                    result.get("auth_state_mismatch"):
                observer = self._select_attack_state(owner_state)
                if observer is not None:
                    resource_id = variant.extra.get("resource_id")
                    experiment = self.authorization_planner.for_target(
                        variant.api_node.get("id", "")
                    )
                    verifier = dict(self.operations_map[experiment.verifier_api])
                    verifier["path"] = re.sub(
                        r"\{" + re.escape(experiment.selector_field) + r"\}",
                        str(resource_id), str(verifier.get("path", "")),
                    )
                    result = self.executor.execute_request(
                        verifier, observer,
                        payload_source_override="BOLA_INDEPENDENT_VERIFY",
                        allow_repair=False, allow_auth_recovery=True,
                    )
            return int(result.get("status", 0) or 0) in (404, 410)
        if (not result_succeeded(result)
                or not pre_attack_response
                or not result_succeeded(pre_attack_response)):
            return False
        return self._mutation_matches(
            result.get("raw_response"), variant.payload or {}, selector,
            resource_type, pre_attack_response.get("raw_response"),
        )

    @staticmethod
    def _mutation_matches(readback, payload, selector, resource_type, baseline):
        readback_items = list(TestStrategyEngine._iter_scalar_items(readback))
        baseline_items = list(TestStrategyEngine._iter_scalar_items(baseline))
        selector_key = AttackStore.normalize_selector(selector, resource_type)
        intended = [
            (AttackStore.normalize_selector(key, resource_type), value)
            for key, value in (payload or {}).items()
            if AttackStore.normalize_selector(key, resource_type) != selector_key
            and value not in (None, "") and not isinstance(value, (dict, list))
        ]
        for key, value in intended:
            after_matches = [
                child for child_key, child in readback_items
                if AttackStore.normalize_selector(child_key, resource_type) == key
            ]
            before_matches = [
                child for child_key, child in baseline_items
                if AttackStore.normalize_selector(child_key, resource_type) == key
            ]
            if any(TestStrategyEngine._exact_value(child, value) for child in after_matches) \
                    and not any(TestStrategyEngine._exact_value(child, value) for child in before_matches):
                return True
        return False

    @staticmethod
    def _find_selector_value(value, selector, resource_type):
        canonical = AttackStore.normalize_selector(selector, resource_type)
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(child, (dict, list)) and \
                        AttackStore.normalize_selector(key, resource_type) == canonical:
                    return child
            for child in value.values():
                found = TestStrategyEngine._find_selector_value(
                    child, selector, resource_type
                )
                if found not in (None, ""):
                    return found
        elif isinstance(value, list):
            for child in value:
                found = TestStrategyEngine._find_selector_value(
                    child, selector, resource_type
                )
                if found not in (None, ""):
                    return found
        return None

    def _reproduce_mutation_with_fresh_resource(
            self, target_node, original_variant, owner_state, attack_state, operation):
        """Create R2, attack it as B, then read it back as A."""
        experiment = self.authorization_planner.for_target(target_node.get("id", ""))
        if experiment is None or not self.authorization_planner.validate(experiment):
            return False
        replay_owner = owner_state
        replay_attacker = attack_state
        provisioned = self.resource_provisioner.provision(target_node, replay_owner)
        if not provisioned.succeeded:
            self._last_provisioning_failure = provisioned.reason
            return False
        self._last_provisioning_failure = ""
        created = provisioned.create_result
        resource_id = provisioned.resource_id

        replay_node = dict(target_node)
        replay_node["path"] = re.sub(
            r"\{" + re.escape(experiment.selector_field) + r"\}",
            str(resource_id), str(target_node.get("path", "")),
        )
        replay_payload = dict(original_variant.payload or {})
        for key in list(replay_payload):
            if AttackStore.normalize_selector(key, experiment.resource_type) == \
                    AttackStore.normalize_selector(experiment.selector_field, experiment.resource_type):
                replay_payload[key] = resource_id
        replay_attack = self.executor.execute_request(
            replay_node, replay_attacker, payload_override=replay_payload,
            payload_source_override="DETERMINISTIC_BOLA_REPLAY",
            allow_repair=False, allow_auth_recovery=True,
        )
        if not result_succeeded(replay_attack) or replay_attack.get("schema_valid") is False:
            return False

        if self._is_credential_rotation_api(target_node):
            return self._verify_password_login(
                resource_id, replay_payload,
                replay_owner.get("actor_id", "password_replay_owner"),
            )

        verifier_node = dict(self.operations_map[experiment.verifier_api])
        verifier_node["path"] = re.sub(
            r"\{" + re.escape(experiment.selector_field) + r"\}",
            str(resource_id), str(verifier_node.get("path", "")),
        )
        verified = self.executor.execute_request(
            verifier_node, replay_owner, payload_source_override="BOLA_OWNER_VERIFY",
            allow_repair=False, allow_auth_recovery=True,
        )
        if operation == "DELETE":
            if int(verified.get("status", 0) or 0) in (401, 403) or \
                    verified.get("auth_state_mismatch"):
                verified = self.executor.execute_request(
                    verifier_node, replay_attacker,
                    payload_source_override="BOLA_INDEPENDENT_VERIFY",
                    allow_repair=False, allow_auth_recovery=True,
                )
            return int(verified.get("status", 0) or 0) in (404, 410)
        if not result_succeeded(verified) or verified.get("schema_valid") is False:
            return False
        return self._mutation_matches(
            verified.get("raw_response"), replay_payload,
            experiment.selector_field, experiment.resource_type,
            created.get("raw_response"),
        )

    def _verify_password_login(self, principal, mutation_payload, actor_id):
        """Verify a password mutation by authenticating the affected principal."""
        _signup, login = ActorBootstrapper(
            self.operations, self.executor
        ).discover_auth_operations()
        if login is None or principal in (None, ""):
            return False
        password = next((
            value for key, value in (mutation_payload or {}).items()
            if ActorBootstrapper._credential_group(key) == "password"
            and value not in (None, "")
        ), None)
        if password is None:
            return False
        login_payload = {}
        for field, raw_meta in (login.get("inputs", {}) or {}).items():
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            original = str(meta.get("original", field))
            group = ActorBootstrapper._credential_group(original)
            if group in {"username", "email"}:
                login_payload[original] = principal
            elif group == "password":
                login_payload[original] = password
        if not login_payload or not any(
                ActorBootstrapper._credential_group(key) == "password"
                for key in login_payload):
            return False
        login_state = StateStore({
            **login_payload,
            "actor_id": str(actor_id),
            "actor_role": "user",
        })
        result = self.executor.execute_request(
            login, login_state, payload_override=login_payload,
            payload_source_override="PASSWORD_CHANGE_VERIFY",
            allow_repair=False, allow_auth_recovery=False,
        )
        return result_succeeded(result)

    @staticmethod
    def _registration_probe_patch(operation, suffix):
        patch = {}
        for field, raw_meta in (operation.get("inputs", {}) or {}).items():
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            if str(meta.get("in", "body")).lower() != "body":
                continue
            original = str(meta.get("original", field))
            group = ActorBootstrapper._credential_group(original)
            if group == "username":
                patch[original] = f"opg_{suffix}"
            elif group == "email":
                patch[original] = f"opg_{suffix}@example.invalid"
            elif group == "password":
                patch[original] = f"OPG!{suffix}Aa1"
            elif group == "phone":
                patch[original] = f"090{suffix[-7:]}"
            elif meta.get("required"):
                enum = list(meta.get("enum", []) or [])
                patch[original] = (
                    enum[0] if enum else meta.get("example", meta.get("default", "probe"))
                )
        return patch

    def _login_registration_probe(self, login, registration_payload, actor_id):
        if login is None:
            return None, None
        grouped = {}
        for key, value in (registration_payload or {}).items():
            group = ActorBootstrapper._credential_group(key)
            if group:
                grouped[group] = value
        payload = {}
        for field, raw_meta in (login.get("inputs", {}) or {}).items():
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            original = str(meta.get("original", field))
            group = ActorBootstrapper._credential_group(original)
            if group in grouped:
                payload[original] = grouped[group]
        if not payload:
            return None, None
        state = StateStore({**payload, "actor_id": actor_id, "actor_role": "user"})
        result = self.executor.execute_request(
            login, state, payload_override=payload,
            payload_source_override="MASS_ASSIGNMENT_LOGIN_VERIFY",
            allow_repair=False, allow_auth_recovery=False,
        )
        return state, result

    def _record_special_security_request(self, operation, state, result, source,
                                         attack_metadata=None):
        self.memory.record_request(
            api_id=operation.get("id", "unknown"),
            method=operation.get("method", "GET").upper(),
            path=result.get("url", operation.get("path", "")),
            status=result.get("status", 0),
            chain=[operation.get("id", "unknown")],
            response_text=result.get("response_text", ""),
            request_payload=result.get("sent_payload", {}),
            payload_source=source,
            sent_headers=result.get("sent_headers", {}),
            sent_query=result.get("sent_query", {}),
            sent_cookies=result.get("sent_cookies", {}),
            actor_id=result.get("actor_id", state.get("actor_id", "default")),
            successful=result.get("successful"),
            outcome_reason=result.get("outcome_reason", ""),
            auth_context=result.get("auth_context", {}),
            elapsed_ms=result.get("elapsed_ms"),
            attack_metadata=attack_metadata or {},
        )

    def _run_registration_mass_assignment_cases(self, summary):
        """Test signup mass assignment and use a privilege differential when available."""
        bootstrapper = ActorBootstrapper(self.operations, self.executor)
        signup, login = bootstrapper.discover_auth_operations()
        if signup is None:
            return
        suffix = uuid.uuid4().hex[:10]
        normal_patch = self._registration_probe_patch(signup, f"n{suffix}")
        elevated_patch = self._registration_probe_patch(signup, f"a{suffix}")
        injected = {
            "admin": True, "isAdmin": True, "is_admin": True,
            "role": "admin", "userRole": "ADMIN", "permissions": ["*"],
        }
        try:
            normal = self.executor.execute_request(
                signup, StateStore({"actor_id": f"mass_normal_{suffix}"}),
                payload_patch=normal_patch,
                payload_source_override="MASS_ASSIGNMENT_CONTROL",
                allow_repair=False, allow_auth_recovery=False,
            )
            attacked = self.executor.execute_request(
                signup, StateStore({"actor_id": f"mass_attack_{suffix}"}),
                payload_patch={**elevated_patch, **injected},
                payload_source_override="ATTACKER_MASS_ASSIGNMENT",
                allow_repair=False, allow_auth_recovery=False,
            )
        except Exception as exc:
            self.memory.record_security_observation({
                "classification": "INFRA_FAILURE", "type": "MASS_ASSIGNMENT",
                "api": signup.get("id", ""),
                "reasoning": f"Registration experiment failed: {type(exc).__name__}: {exc}",
            })
            return


        self._record_special_security_request(
            signup, StateStore({"actor_id": f"mass_normal_{suffix}"}), normal,
            "MASS_ASSIGNMENT_CONTROL",
        )
        self._record_special_security_request(
            signup, StateStore({"actor_id": f"mass_attack_{suffix}"}), attacked,
            "ATTACKER_MASS_ASSIGNMENT",
            attack_metadata={
                "strategy": "param_pollution",
                "technique": "mass_assignment",
                "description": "Inject privilege fields during account registration",
                "mutation": {"injected_fields": sorted(injected)},
            },
        )

        if not result_succeeded(attacked):
            return

        normal_state, normal_login = self._login_registration_probe(
            login, normal.get("sent_payload", normal_patch), f"mass_normal_{suffix}"
        )
        elevated_state, elevated_login = self._login_registration_probe(
            login, attacked.get("sent_payload", elevated_patch), f"mass_attack_{suffix}"
        )
        privilege_verified = False
        privileged_api = ""
        if (normal_state is not None and elevated_state is not None
                and result_succeeded(normal_login or {})
                and result_succeeded(elevated_login or {})):
            candidates = [
                op for op in self.operations
                if op.get("privileged_function_hint")
                and not op.get("potentially_destructive")
                and str(op.get("method", "GET")).upper() == "GET"
                and not self._is_auth_lifecycle_api(op)
            ]
            for privileged in candidates:
                control = self.executor.execute_request(
                    privileged, normal_state,
                    payload_source_override="MASS_ASSIGNMENT_CONTROL_VERIFY",
                    allow_repair=False, allow_auth_recovery=False,
                )
                elevated = self.executor.execute_request(
                    privileged, elevated_state,
                    payload_source_override="MASS_ASSIGNMENT_PRIVILEGE_VERIFY",
                    allow_repair=False, allow_auth_recovery=False,
                )
                if int(control.get("status", 0) or 0) in (401, 403, 404) \
                        and result_succeeded(elevated):
                    privilege_verified = True
                    privileged_api = privileged.get("id", "")
                    break

        api_id = signup.get("id", "unknown")
        if privilege_verified:
            finding = {
                "type": "MASS_ASSIGNMENT", "severity": "HIGH", "confidence": 0.96,
                "api": api_id, "method": signup.get("method", "POST"),
                "path": signup.get("path", ""), "status": attacked.get("status", 0),
                "strategy": "mass_assignment",
                "evidence": [
                    "Injected account authenticated and accessed a function denied to the control account",
                    f"Privilege verifier: {privileged_api}",
                ],
                "reasoning": "Registration accepted privilege fields and the resulting privilege was verified.",
                "injected_fields": sorted(injected),
            }
            self.memory.record_finding(finding)
            self.memory.record_vulnerability(api_id, attacked.get("status", 0))
            self.memory.record_experiment_stage(
                api_id, "confirmed", finding["reasoning"], status="CONFIRMED"
            )
        else:
            summary["suspected"] += 1
            evidence = ["Registration accepted injected privilege fields with a 2xx response"]
            if elevated_login and result_succeeded(elevated_login):
                evidence.append("The injected account could authenticate successfully")
            self.memory.record_security_observation({
                "classification": "SUSPECTED", "type": "MASS_ASSIGNMENT",
                "api": api_id, "method": signup.get("method", "POST"),
                "path": signup.get("path", ""), "confidence": 0.7,
                "evidence": evidence,
                "reasoning": "Privilege input was accepted, but no differential admin verifier was available.",
            })

    @staticmethod
    def _select_same_role_actor(actor_contexts, owner_actor_id, owner_role):
        normalized_owner_role = str(owner_role or "").strip().casefold()
        if normalized_owner_role in {"", "unknown", "anonymous", "none", "null"}:
            return None
        for actor in actor_contexts.all():
            if actor.actor_id == owner_actor_id or actor.role == "anonymous":
                continue
            if str(actor.role).strip().casefold() == normalized_owner_role:
                return actor.to_state_store()
        return None
