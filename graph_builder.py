import os
from collections import defaultdict
from rule_inference_layer import RuleInferenceLayer
from llm_planner import LLMPlanner

class DependencyGraphBuilder:
    def __init__(self, operations: list, rule_layer: RuleInferenceLayer, planner: LLMPlanner):
        self.operations = operations
        self.rule_layer = rule_layer
        self.planner = planner
        self.adjacency_list = {op['id']: [] for op in self.operations}
        
    def update_edge_confidence(self, api_out, api_in, success):
        """Runtime Edge Reinforcement: Tự động tiến hóa đồ thị dựa trên kết quả Fuzzing."""
        if api_out not in self.adjacency_list: return
        for edge in self.adjacency_list[api_out]:
            if edge['to'] == api_in:
                # Nếu Fuzzing thành công -> Tăng 10% điểm. Nếu thất bại -> Phạt 20%
                multiplier = 1.1 if success else 0.8
                edge['max_confidence'] = round(min(1.0, edge['max_confidence'] * multiplier), 2)
                for dep in edge.get('dependencies', []):
                    dep['confidence'] = round(min(1.0, dep['confidence'] * multiplier), 2)
                break

    def build_scientific_odg(self, output_file="ODG_Scientific_Final.dot"):
        """Xây dựng đồ thị Sparse Weighted ODG sử dụng Inverted Semantic Index."""
        # 0b. Thu thập field 'unknown' → batch gọi LLM 1 lần duy nhất
        all_unknown = set()
        for op in self.operations:
            for f in list(op.get('outputs', {}).keys()) + list(op.get('inputs', {}).keys()):
                norm = self.rule_layer.normalize_field(f)
                if self.rule_layer.classify_semantic(norm) == 'unknown' and not self.rule_layer.is_noisy(norm):
                    all_unknown.add(norm)

        if all_unknown:
            print(f"[*] LLM đang phân loại {len(all_unknown)} field 'unknown': {sorted(all_unknown)}")
            self.planner.classify_unknown_fields(list(all_unknown))

        # 1. Xây dựng Inverted Semantic Index (kèm format từ metadata)
        outputs_index = defaultdict(list)
        inputs_index = defaultdict(list)
        
        for op in self.operations:
            method = op.get('method', '').upper()
            op_id = op['id']
            
            # Index Outputs
            if method != 'DELETE': # Xóa bẫy Nghịch lý DELETE
                for f_out, meta_out in op.get('outputs', {}).items():
                    norm_out = self.rule_layer.normalize_field(f_out)
                    sem_out  = self.rule_layer.classify_semantic(norm_out)
                    fmt_out  = meta_out.get('format', 'unknown') if isinstance(meta_out, dict) else 'unknown'
                    outputs_index[sem_out].append({
                        'api_id': op_id, 'method': method,
                        'field': f_out, 'norm_field': norm_out, 'sem': sem_out, 'format': fmt_out
                    })
                    
            # Index Inputs
            for f_in, meta_in in op.get('inputs', {}).items():
                norm_in = self.rule_layer.normalize_field(f_in)
                sem_in  = self.rule_layer.classify_semantic(norm_in)
                fmt_in  = meta_in.get('format', 'unknown') if isinstance(meta_in, dict) else 'unknown'
                inputs_index[sem_in].append({
                    'api_id': op_id, 'method': method,
                    'field': f_in, 'norm_field': norm_in, 'sem': sem_in, 'format': fmt_in
                })

        # 1b. LLM Identity Clustering
        all_identity_fields = list(set(
            item['norm_field']
            for bucket in [outputs_index.get('identity', []), inputs_index.get('identity', [])]
            for item in bucket
        ))
        if all_identity_fields:
            print(f"[*] LLM Identity Clustering: {len(all_identity_fields)} fields...")
            self.planner.cluster_identities(all_identity_fields)

        raw_edges = defaultdict(list)
        
        for sem_type in outputs_index.keys():
            out_list = outputs_index[sem_type]
            in_list  = inputs_index.get(sem_type, [])
            
            for out_item in out_list:
                for in_item in in_list:
                    if out_item['api_id'] == in_item['api_id']: continue
                    
                    base_score, match_type = self.rule_layer.calculate_confidence(
                        out_item['field'], out_item['norm_field'], out_item['sem'], out_item['format'],
                        in_item['field'],  in_item['norm_field'],  in_item['sem'],  in_item['format']
                    )
                    
                    if base_score >= 0.25:   # Hạ ngưỡng: giữ cả fallback candidate
                        dir_score  = self.rule_layer.get_directionality_score(out_item['method'], in_item['method'])
                        final_score = base_score * dir_score
                        
                        if final_score >= 0.25:
                            edge_key = (out_item['api_id'], in_item['api_id'])
                            raw_edges[edge_key].append({
                                'producer_field': out_item['field'],
                                'consumer_field': in_item['field'],
                                'confidence':     round(final_score, 2),
                                'match_type':     match_type,
                                'semantic_type':  sem_type
                            })

        def classify_importance(confidence: float) -> str:
            """Soft-rank: primary / secondary / fallback theo ngưỡng confidence."""
            if confidence >= 0.75: return 'primary'
            if confidence >= 0.45: return 'secondary'
            return 'fallback'

        def edge_type_from_deps(deps: list) -> str:
            """Phân loại cạnh dựa theo dep quan trọng nhất."""
            if any(d['importance'] == 'primary'   for d in deps): return 'strong'
            if any(d['importance'] == 'secondary' for d in deps): return 'medium'
            return 'fallback'

        # ── Tổng hợp raw_edges thành adjacency_list ─────────────────────────────
        dot = "digraph G {\n    rankdir=LR;\n"
        dot += "    node [shape=box, style=filled, color=\"#E3F2FD\", fontname=\"Arial\"];\n"
        dot += "    edge [fontname=\"Arial\", fontsize=9];\n\n"

        for op in self.operations:
            dot += f'    "{op["id"]}";\n'

        # Tập hợp các API đã có ít nhất 1 cạnh mạnh đi ra
        has_strong_outgoing = set()
        edges_count = 0

        for (api_out, api_in), deps in raw_edges.items():
            # Dedup field pairs, giữ score cao nhất cho mỗi cặp
            best_per_pair = {}
            for d in deps:
                pair_key = f"{d['producer_field']}|{d['consumer_field']}"
                if pair_key not in best_per_pair or d['confidence'] > best_per_pair[pair_key]['confidence']:
                    best_per_pair[pair_key] = d

            sorted_deps = sorted(best_per_pair.values(), key=lambda x: x['confidence'], reverse=True)

            # Chia thành strong và fallback
            strong_deps   = [d for d in sorted_deps if d['confidence'] >= 0.45]
            fallback_deps = [d for d in sorted_deps if d['confidence'] <  0.45]

            if strong_deps:
                selected = strong_deps[:3]        # Tối đa 3 dep mạnh
                has_strong_outgoing.add(api_out)
            else:
                selected = fallback_deps[:3]      # Fallback top-3 (AutoRestTest-style)

            if not selected:
                continue

            # Gắn nhãn importance cho từng dep
            for dep in selected:
                dep['importance'] = classify_importance(dep['confidence'])

            max_conf   = selected[0]['confidence']
            edge_type  = edge_type_from_deps(selected)
            primary_sem = selected[0]['semantic_type']

            self.adjacency_list[api_out].append({
                'to':             api_in,
                'dependencies':   selected,
                'max_confidence': max_conf,
                'edge_type':      edge_type,  # 'strong' | 'medium' | 'fallback'
            })

            label_lines = [f"{d['producer_field']} → {d['consumer_field']} [{d['importance']}]" for d in selected]
            label = "\\n".join(label_lines) + f"\\nConf: {max_conf}"

            color = "#999999"  # fallback
            if edge_type == 'strong':
                color = "#1E88E5" if primary_sem == 'identity' else "#E53935" if primary_sem == 'auth/workflow' else "#43A047" if primary_sem == 'finance' else "#555555"
            elif edge_type == 'medium':
                color = "#F9A825"

            dot += f'    "{api_out}" -> "{api_in}" [label="{label}", color="{color}", fontcolor="{color}"];\n'
            edges_count += 1

        # ── AutoRestTest-style fallback: API hoàn toàn bị cô lập → top-3 candidate ──
        # Xây inverted similarity index đơn giản: tìm top-3 outgoing cho node chưa có cạnh
        isolated_apis = [
            op['id'] for op in self.operations
            if op['id'] not in has_strong_outgoing and not self.adjacency_list[op['id']]
        ]
        if isolated_apis:
            print(f"[*] Fallback top-k injection cho {len(isolated_apis)} node bị cô lập...")
            for api_out in isolated_apis:
                fallback_candidates = []
                for (src, dst), deps in raw_edges.items():
                    if src != api_out: continue
                    for d in deps:
                        fallback_candidates.append((dst, d))
                # Lấy top-3 dep bất kể ngưỡng
                fallback_candidates.sort(key=lambda x: x[1]['confidence'], reverse=True)
                seen_dst = set()
                for dst, dep in fallback_candidates:
                    if dst in seen_dst: continue
                    dep['importance'] = 'fallback'
                    self.adjacency_list[api_out].append({
                        'to':             dst,
                        'dependencies':   [dep],
                        'max_confidence': dep['confidence'],
                        'edge_type':      'fallback',
                    })
                    seen_dst.add(dst)
                    if len(seen_dst) >= 3: break

        dot += "}\n"
        with open(output_file, 'w', encoding='utf-8') as f: f.write(dot)
        print(f"[*] Đã tạo đồ thị Sparse Weighted ODG (V4-SoftRank) với {edges_count} cạnh.")

        # ── Safety Net: đảm bảo mọi required/path input đều có incoming edge ──
        injected = self._build_required_input_safety_net()
        if injected:
            print(f"[*] Safety-Net injected {injected} cạnh thiếu cho required/path inputs.")
        
        return self.adjacency_list

    def _build_required_input_safety_net(self) -> int:
        """
        Safety Net: Quét toàn bộ API sau khi build xong đồ thị.
        Nếu một required field hoặc path parameter chưa được covered bởi
        bất kỳ incoming edge nào → tìm provider tốt nhất và inject cạnh.
        Cơ chế tìm kiếm: fuzzy normalized name matching trên toàn bộ outputs.
        """
        import re

        def _norm(name: str) -> str:
            s = re.sub(r'([a-z])([A-Z])', r'\\1 \\2', str(name))
            s = re.sub(r'[-_\\.\\s]', '', s)
            return s.lower()

        def _tokens(name: str) -> set:
            s = re.sub(r'([a-z])([A-Z])', r'\\1 \\2', str(name))
            return set(re.split(r'[-_\\.\\s]', s.lower()))

        # --- Xây output lookup: norm_name → list of (api_id, original_field) ---
        output_lookup: dict = defaultdict(list)
        for op in self.operations:
            if op.get('method', '').upper() == 'DELETE':
                continue
            for f_out, meta_out in op.get('outputs', {}).items():
                output_lookup[_norm(f_out)].append((op['id'], f_out))
                # Thêm cả token-set để hỗ trợ partial match (vehicleId → vehicle id)
                for tok in _tokens(f_out):
                    if len(tok) > 2:  # bỏ qua token quá ngắn
                        output_lookup[tok].append((op['id'], f_out))

        # --- Xây incoming edge set: (api_in, norm_consumer_field) → True ---
        covered: set = set()
        for api_out, edges in self.adjacency_list.items():
            for edge in edges:
                api_in = edge['to']
                for dep in edge.get('dependencies', []):
                    covered.add((api_in, _norm(dep.get('consumer_field', ''))))

        injected_count = 0

        for op in self.operations:
            api_in = op['id']
            for field_name, meta in op.get('inputs', {}).items():
                if not isinstance(meta, dict):
                    continue
                is_required = meta.get('required', False)
                location    = meta.get('in', 'body')
                if not is_required and location != 'path':
                    continue   # chỉ xét required hoặc path param

                norm_consumer = _norm(field_name)
                if (api_in, norm_consumer) in covered:
                    continue   # đã có incoming edge cover field này

                # Tìm provider tốt nhất trong output_lookup
                # Thử exact match trước, rồi token-based
                candidates_raw = output_lookup.get(norm_consumer, [])
                if not candidates_raw:
                    # Thử khớp từng token quan trọng (loại bỏ "id", "uuid", "no")
                    SKIP_TOKENS = {'id', 'uuid', 'no', 'ref', 'key'}
                    for tok in _tokens(field_name):
                        if tok in SKIP_TOKENS:
                            continue
                        hits = output_lookup.get(tok, [])
                        candidates_raw.extend(hits)

                # Lọc bỏ self-loop và API đã có edge đến api_in
                existing_providers = {
                    e['to'] for api_src, edges in self.adjacency_list.items()
                    for e in edges if api_src != api_in
                }
                # Chọn provider tốt nhất: ưu tiên POST/PUT (tạo resource) hơn GET
                METHOD_PRIORITY = {'POST': 3, 'PUT': 2, 'PATCH': 2, 'GET': 1, 'DELETE': 0}
                best_provider = None
                best_score    = -1

                seen_providers = set()
                for (src_api, f_out) in candidates_raw:
                    if src_api == api_in or src_api in seen_providers:
                        continue
                    seen_providers.add(src_api)
                    src_op = next((o for o in self.operations if o['id'] == src_api), None)
                    if not src_op:
                        continue
                    method_score = METHOD_PRIORITY.get(src_op.get('method', '').upper(), 1)
                    # Exact norm match → điểm cao hơn token match
                    exact_bonus  = 2 if _norm(f_out) == norm_consumer else 0
                    score        = method_score + exact_bonus
                    if score > best_score:
                        best_score    = score
                        best_provider = (src_api, f_out)

                if not best_provider:
                    continue

                src_api, f_out = best_provider

                # Kiểm tra xem cạnh src_api → api_in đã tồn tại chưa
                existing_edge = next(
                    (e for e in self.adjacency_list.get(src_api, []) if e['to'] == api_in),
                    None
                )
                new_dep = {
                    'producer_field': f_out,
                    'consumer_field': meta.get('original', field_name),
                    'confidence':     0.40,   # safety-net: secondary confidence
                    'match_type':     'safety_net',
                    'semantic_type':  'identity' if location == 'path' else 'unknown',
                    'importance':     'secondary',
                }

                if existing_edge:
                    # Chỉ thêm dep mới nếu chưa có cặp field này
                    dep_key = f"{f_out}|{meta.get('original', field_name)}"
                    existing_keys = {
                        f"{d['producer_field']}|{d['consumer_field']}"
                        for d in existing_edge.get('dependencies', [])
                    }
                    if dep_key not in existing_keys:
                        existing_edge['dependencies'].append(new_dep)
                        existing_edge['max_confidence'] = max(
                            existing_edge['max_confidence'], new_dep['confidence']
                        )
                        covered.add((api_in, norm_consumer))
                        injected_count += 1
                else:
                    # Tạo cạnh mới hoàn toàn
                    self.adjacency_list[src_api].append({
                        'to':             api_in,
                        'dependencies':   [new_dep],
                        'max_confidence': new_dep['confidence'],
                        'edge_type':      'medium',
                    })
                    covered.add((api_in, norm_consumer))
                    injected_count += 1
                    print(f"  [SafetyNet] Inject cạnh: {src_api} → {api_in} "
                          f"({f_out} → {meta.get('original', field_name)}) "
                          f"[{location}, required={is_required}]")

        return injected_count
