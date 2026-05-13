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
                    
                    if base_score >= 0.5:
                        dir_score = self.rule_layer.get_directionality_score(out_item['method'], in_item['method'])
                        final_score = base_score * dir_score
                        
                        if final_score >= 0.5:
                            edge_key = (out_item['api_id'], in_item['api_id'])
                            raw_edges[edge_key].append({
                                'producer_field': out_item['field'],
                                'consumer_field': in_item['field'],
                                'confidence': round(final_score, 2),
                                'match_type': match_type,
                                'semantic_type': sem_type
                            })
                            
        # 3. Tổng hợp và xuất Đồ thị (Merged Edge Metadata)
        dot = "digraph G {\n    rankdir=LR;\n"
        dot += "    node [shape=box, style=filled, color=\"#E3F2FD\", fontname=\"Arial\"];\n"
        dot += "    edge [fontname=\"Arial\", fontsize=9];\n\n"

        for op in self.operations:
            dot += f'    "{op["id"]}";\n'

        edges_count = 0
        for (api_out, api_in), deps in raw_edges.items():
            # Lọc bỏ các cạnh trùng lặp field
            unique_deps = {f"{d['producer_field']}_{d['consumer_field']}": d for d in deps}.values()
            sorted_deps = sorted(unique_deps, key=lambda x: x['confidence'], reverse=True)
            
            top_deps = sorted_deps[:2]
            max_conf = top_deps[0]['confidence']
            primary_sem = top_deps[0]['semantic_type']
            
            self.adjacency_list[api_out].append({
                'to': api_in,
                'dependencies': top_deps,
                'max_confidence': max_conf
            })
            
            label_lines = [f"{d['producer_field']} → {d['consumer_field']} [{d['semantic_type']}]" for d in top_deps]
            label = "\\n".join(label_lines) + f"\\nConf: {max_conf}"
            
            color = "#555555"
            if primary_sem == 'identity': color = "#1E88E5"
            elif primary_sem == 'auth/workflow': color = "#E53935"
            elif primary_sem == 'finance': color = "#43A047"
            
            dot += f'    "{api_out}" -> "{api_in}" [label="{label}", color="{color}", fontcolor="{color}"];\n'
            edges_count += 1

        dot += "}\n"
        with open(output_file, 'w', encoding='utf-8') as f: f.write(dot)
        print(f"[*] Đã tạo đồ thị Scalable OPG (V3) với {edges_count} cạnh (O(K log K) Indexed).")
        
        return self.adjacency_list
