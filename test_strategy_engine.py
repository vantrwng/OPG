import json
import re
import math
import asyncio
import logging
from state_store import StateStore
from runtime_executor import RequestExecutor
from knowledge_memory import KnowledgeMemory
from local_mutator import AsyncFuzzEngine
from attack_store import AttackStore, get_attack_store
from state_store import MultiActorContextStore

# ── Agent imports (optional — graceful fallback if Ollama not available) ─────────
_AGENTS_AVAILABLE = False
try:
    from attacker_agent import AttackerAgent, AttackVariant
    from auditor_agent import AuditorAgent, AuditResult
    _AGENTS_AVAILABLE = True
except ImportError:
    pass

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

    def __init__(self, operations, adjacency_list, request_executor, graph_builder, knowledge_memory, beam_width=5):
        self.operations = operations
        self.adjacency_list = adjacency_list
        self.executor = request_executor
        self.graph_builder = graph_builder
        self.memory = knowledge_memory
        
        self.scorer = HeuristicScorer()
        self.beam_width = beam_width
        self.actor_contexts = MultiActorContextStore()
        self.operations_map = {op['id']: op for op in self.operations}

        # ── Attack Store (shared cross-beam) ─────────────────────────────────
        self.attack_store: AttackStore = get_attack_store()

        # ── Agent instances ─────────────────────────────────────────────────
        if _AGENTS_AVAILABLE:
            self._attacker = AttackerAgent(attack_store=self.attack_store)
            self._auditor  = AuditorAgent()
            log.info("[Engine] ✅ 3-Agent Pipeline enabled (Attacker + Auditor)")
        else:
            self._attacker = None
            self._auditor  = None
            log.warning("[Engine] ⚠ Agents not available — running without Attacker/Auditor")
        
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
            return re.sub(r'[_\-\.\s]', '', str(name)).lower()

        # ── Hướng 1: Chỉ xét field required hoặc path parameter ──────────────
        missing_fields = []
        state_keys_norm = set(_norm(k) for k in state.memory.keys())

        for field_name, meta in inputs_schema.items():
            if not isinstance(meta, dict):
                continue

            is_required = meta.get("required", False)
            location    = meta.get("in", "body")

            # Bỏ qua nếu optional và không phải path param
            if not is_required and location != "path":
                continue

            original = meta.get("original", field_name)
            orig_norm = _norm(original)
            fld_norm  = _norm(field_name)

            if orig_norm not in state_keys_norm and fld_norm not in state_keys_norm:
                missing_fields.append(orig_norm)

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
                    sent_headers=exec_result.get("sent_headers", {})
                )

                current_chain.append(provider_id)

                if exec_result["status"] in (200, 201, 202):
                    resolved = True
                    print(f"{indent}[+] Resolve '{missing_field}' thành công via '{provider_id}'!")
                    break
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
                    sent_headers=exec_result.get("sent_headers", {})
                )
                
                # --- [GIAI ĐOẠN 1] Local Mutator Blasting ---
                # Chỉ bắn rác khi payload gốc là hợp lệ (status 200, 201, 202, 204)
                if status in (200, 201, 202, 204) and exec_result.get("sent_payload"):
                    print(f"[{current_api}] 🚀 Bắt đầu bắn xối xả (Blasting) 50 requests rác để tìm lỗi 500...")
                    try:
                        # TestStrategyEngine.run() là sync — asyncio.run() luôn an toàn ở đây.
                        # KHÔNG dùng loop.run_until_complete() vì sẽ raise RuntimeError
                        # nếu có running loop (e.g. khi chạy trong Jupyter / async wrapper).
                        blast_results = asyncio.run(AsyncFuzzEngine.blast_api(
                            url=exec_result.get("url"),
                            method=api_node.get("method", "GET").upper(),
                            headers=exec_result.get("sent_headers", {}),
                            valid_payload=exec_result.get("sent_payload", {}),
                            num_requests=50
                        ))
                            
                        for br in blast_results:
                            b_status = br["status"]
                            # Ghi nhận request rác vào report
                            self.memory.record_request(
                                api_id=current_api,
                                method=api_node.get("method", "GET").upper(),
                                path=exec_result.get("url", api_node.get("path", "/")),
                                status=b_status,
                                chain=beam['chain'],
                                response_text=br.get("text", br.get("error", "")),
                                request_payload=br.get("payload", {}),
                                payload_source="LOCAL_MUTATOR",
                                sent_headers=exec_result.get("sent_headers", {})
                            )
                            # Nếu ra 500, đánh dấu lỗi
                            if b_status >= 500:
                                if not self.memory.is_vulnerability_found(current_api, b_status):
                                    vulnerabilities.append({
                                        "api": current_api,
                                        "status": b_status,
                                        "details": ["Gây ra lỗi 500 bằng Local Mutator"],
                                        "type": "Crash/500"
                                    })
                                    self.memory.record_vulnerability(current_api, b_status)
                                    self.memory.record_finding({
                                        "api": current_api,
                                        "method": api_node.get("method", "GET").upper(),
                                        "path": exec_result.get("url", api_node.get("path", "/")),
                                        "status": b_status,
                                        "details": ["Gây ra lỗi 500 bằng Local Mutator"],
                                        "type": "Crash/500",
                                        "chain": beam['chain']
                                    })
                    except Exception as e:
                        print(f"[{current_api}] ❌ Lỗi khi Blasting: {str(e)}")
                # --- End Local Mutator ---
                
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

                # ── [GIAI ĐOẠN 2] 3-Agent Pipeline: Attacker + Auditor ───────────────
                # Depth 1 = "Warm-up round": chỉ lưu baseline + harvest IDs vào AttackStore
                #   → StateStore chưa đủ context (token, ID) để sinh attack có nghĩa
                # Depth >= 2: đã có baseline + IDs → chạy đầy đủ Attacker + Auditor
                agent_score_bonus = 0.0
                if status in (200, 201, 202) and self._attacker and self._auditor:
                    if depth == 1:
                        # ── Warm-up: chỉ lưu baseline + harvest IDs ──────────────
                        print(f"[{current_api}] 🔥 Depth 1 warm-up — lưu baseline & harvest IDs...")
                        current_state.set_baseline(current_api, exec_result)
                        raw_resp = exec_result.get("raw_response")
                        if raw_resp:
                            own_ctx = {
                                "actor_id": current_state.get("actor_id", "default"),
                                "user_id": current_state.get("user_id") or current_state.get("id"),
                                "email":   current_state.get("email"),
                            }
                            n = self.attack_store.record_from_response(
                                api_id=current_api,
                                response_json=raw_resp,
                                endpoint=exec_result.get("url", api_node.get("path", "")),
                                user_context={k: v for k, v in own_ctx.items() if v},
                                owner_actor_id=own_ctx["actor_id"],
                                confidence=0.9,
                            )
                            if n:
                                print(f"[{current_api}] 📦 Harvested {n} resource IDs → AttackStore")
                    else:
                        # ── Depth >= 2: Chạy đầy đủ pipeline ────────────────────
                        agent_score_bonus = self._run_3agent_pipeline(
                            api_node=api_node,
                            current_state=current_state,
                            exec_result=exec_result,
                            beam_chain=beam['chain'],
                            vulnerabilities=vulnerabilities,
                        )

                if len(beam['chain']) >= 2:
                    prev_api = beam['chain'][-2]
                    is_success = not exec_result["edge_failure"]
                    
                    if not is_success and exec_result.get("repair_skipped"):
                        stats = self.memory.endpoint_stats.get(current_api, {}).get("status_counts", {})
                        has_prior_success = any(int(st) in (200, 201, 202) for st in stats.keys())
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
        raw_response = exec_result.get("raw_response")
        if raw_response:
            own_ctx = {
                "actor_id": current_state.get("actor_id", "default"),
                "user_id": current_state.get("user_id") or current_state.get("id"),
                "email":   current_state.get("email"),
            }
            n_harvested = self.attack_store.record_from_response(
                api_id=api_id,
                response_json=raw_response,
                endpoint=exec_result.get("url", api_node.get("path", "")),
                user_context={k: v for k, v in own_ctx.items() if v},
                owner_actor_id=own_ctx["actor_id"],
                confidence=0.9,
            )
            if n_harvested:
                log.info(f"[AttackStore] Harvested {n_harvested} IDs from {api_id}")

        # Prefer a distinct principal for authorization tests. The owner state
        # remains the baseline; the selected state supplies the attack token.
        attack_state = self._select_attack_state(current_state)

        # ── Bước 3: Attacker Agent sinh variants ──────────────────────────────
        valid_payload = exec_result.get("sent_payload", {})
        try:
            attack_variants = self._attacker.generate_attacks(
                api_node=api_node,
                state=attack_state,
                valid_payload=valid_payload,
                valid_response=raw_response,
            )
        except Exception as e:
            log.error(f"[AttackerAgent] Error generating attacks for {api_id}: {e}")
            return 0.0

        if not attack_variants:
            log.info(f"[AttackerAgent] No attack variants generated for {api_id}")
            return 0.0

        log.info(f"\033[95m[3-Agent]\033[0m Running {len(attack_variants)} attack variants on {api_id}")

        # ── Bước 4 & 5: Thực thi variants + Audit ────────────────────────────
        baseline_response = current_state.get_baseline(api_id)

        for variant in attack_variants:
            # Tạo modified api_node với path đã bị biến đổi
            attack_node = dict(variant.api_node)
            attack_node["path"] = variant.path

            try:
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
                )

                # ── Auditor Agent: phân tích response ─────────────────────────
                variant_info = {
                    "strategy":    variant.strategy,
                    "description": variant.description,
                    "extra":       {
                        **variant.extra,
                        "attacker_actor_id": attack_state.get("actor_id", "default"),
                        "owner_actor_id": current_state.get("actor_id", "default"),
                    },
                }

                audit_result = self._auditor.audit(
                    attack_variant_info=variant_info,
                    attack_response=attack_exec,
                    baseline_response=baseline_response,
                    state=attack_state,
                    api_node=api_node,
                )

                if audit_result.classification == "SUSPECTED":
                    self.memory.record_security_observation({
                        "classification": "SUSPECTED",
                        "type": audit_result.bola_type or "BROKEN_ACCESS_CONTROL",
                        "api": api_id,
                        "method": attack_node.get("method", "GET").upper(),
                        "path": attack_exec.get("url", variant.path),
                        "strategy": variant.strategy,
                        "owner_actor_id": current_state.get("actor_id", "default"),
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
                log.error(f"[3-Agent] Error running variant {variant.strategy} on {api_id}: {e}")
                continue

        return total_bonus

    def _select_attack_state(self, owner_state):
        owner_actor_id = owner_state.get("actor_id", "default")
        for actor in self.actor_contexts.all():
            if actor.actor_id == owner_actor_id:
                continue
            base = {
                "auth_header_name": owner_state.get("auth_header_name", "Authorization"),
                "auth_header_prefix": owner_state.get("auth_header_prefix", "Bearer"),
            }
            return actor.to_state_store(base=base)
        return owner_state
