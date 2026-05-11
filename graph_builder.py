import re
import os
import json
from collections import defaultdict
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_MODELS_ENDPOINT = "https://models.inference.ai.azure.com"


class DependencyGraphBuilder:
    def __init__(self, operations):
        self.operations = operations
        self.adjacency_list = {op['id']: [] for op in self.operations}
        self._idf_cache = {}        # Cache tần suất xuất hiện của field
        self._llm_cache = {}        # Cache kết quả phân loại của Gemini
        
    def normalize_field(self, field_name):
        """Chuyển đổi CamelCase, snake_case, kebab-case về dạng space-separated lowercase."""
        s = re.sub(r'([a-z])([A-Z])', r'\1 \2', field_name)
        s = re.sub(r'[-_\.]', ' ', s)
        return ' '.join(s.lower().split())

    def is_noisy(self, norm_field):
        """Contextual Blacklist: Chỉ chặn nếu khớp chính xác toàn bộ từ."""
        exact_noise = {
            'name', 'title', 'description', 'message', 'content', 'note', 'text', 
            'success', 'error', 'url', 'picture url', 
            'video url', 'created at', 'updated at', 'category'
        }
        return norm_field in exact_noise

    def get_stopword_weight(self, norm_field):
        """Stopword Penalty: Phạt điểm nếu trường chỉ chứa duy nhất 1 Generic Token."""
        GENERIC_TOKENS = {'status', 'state', 'number', 'type'}
        tokens = norm_field.split()
        if len(tokens) == 1 and tokens[0] in GENERIC_TOKENS:
            return 0.4 # Phạt giảm điểm mạnh
        return 1.0

    def classify_semantic(self, norm_field):
        """Phân loại ngữ nghĩa bằng Tokenized Matching và Aliasing."""
        tokens = norm_field.split()
        
        # Identity (bao gồm Aliases)
        if any(kw in tokens for kw in ['id', 'uuid', 'email', 'phone', 'no', 'ref', 'vin', 'member', 'customer', 'subscriber', 'account', 'user']):
            return 'identity'
            
        # Auth / Workflow
        if any(kw in tokens for kw in ['token', 'session', 'role', 'cookie', 'hash', 'key', 'code', 'status', 'state']):
            return 'auth/workflow'
            
        # Finance
        if any(kw in tokens for kw in ['balance', 'credit', 'amount', 'price', 'fee']):
            return 'finance'
            
        return 'unknown'

    def llm_classify_unknown_fields(self, unknown_fields):
        """
        Gọi GitHub Models (gpt-4o-mini) để phân loại các field 'unknown' mà rule-based không xử lý được.
        Sử dụng GitHub PAT — miễn phí và quota cao.
        """
        if not unknown_fields:
            return
        try:
            client = OpenAI(
                base_url=GITHUB_MODELS_ENDPOINT,
                api_key=GITHUB_TOKEN
            )
            fields_list = "\n".join([f"- {f}" for f in unknown_fields])
            prompt = f"""You are an API security expert analyzing REST API field dependencies.

Classify each field name below into ONE of these semantic categories:
- "identity": Unique identifiers for resources (e.g. user_id, vin, order_no, patient_ref, pincode as location id)
- "auth/workflow": Authentication tokens, session keys, workflow state codes
- "finance": Monetary values, prices, balances, fees
- "unknown": Cannot be determined

Respond ONLY with a valid JSON object. Keys are field names, values are the category string.
Example: {{"vin": "identity", "conversion_param": "unknown", "pincode": "identity"}}

Fields to classify:
{fields_list}"""

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            result = json.loads(response.choices[0].message.content)
            print(f"  [LLM] GitHub Models (gpt-4o-mini) OK")
            for field, category in result.items():
                if category in ('identity', 'auth/workflow', 'finance'):
                    self._llm_cache[field] = category
                    print(f"  [LLM] '{field}' \u2192 {category}")
        except Exception as e:
            if '429' in str(e) or 'quota' in str(e).lower() or 'rate' in str(e).lower():
                print("  [LLM] Rate limit — bỏ qua LLM layer, tiếp tục với rule-based.")
            else:
                print(f"  [LLM] Warning: {e}")


    def classify_semantic(self, norm_field):
        """Phân loại ngữ nghĩa: Rule-based trước, LLM cache làm fallback."""
        tokens = norm_field.split()
        
        # Identity (bao gồm Aliases)
        if any(kw in tokens for kw in ['id', 'uuid', 'email', 'phone', 'no', 'ref', 'vin', 'member', 'customer', 'subscriber', 'account', 'user']):
            return 'identity'
            
        # Auth / Workflow
        if any(kw in tokens for kw in ['token', 'session', 'role', 'cookie', 'hash', 'key', 'code', 'status', 'state']):
            return 'auth/workflow'
            
        # Finance
        if any(kw in tokens for kw in ['balance', 'credit', 'amount', 'price', 'fee']):
            return 'finance'

        # LLM Fallback: Kiểm tra cache của Gemini
        if norm_field in self._llm_cache:
            return self._llm_cache[norm_field]
            
        return 'unknown'

    def calculate_jaccard(self, norm_out, norm_in):
        """Tính Jaccard Similarity cơ bản."""
        set1 = set(norm_out.split())
        set2 = set(norm_in.split())
        if not set1 or not set2: return 0.0
        return float(len(set1.intersection(set2))) / len(set1.union(set2))

    def build_idf_index(self):
        """Xây dựng IDF Index: Đếm tần suất xuất hiện của mỗi field trên toàn bộ API (inputs + outputs)."""
        freq = defaultdict(int)
        total = len(self.operations)
        for op in self.operations:
            seen = set()
            # Đếm cả inputs và outputs
            all_fields = list(op.get('outputs', {}).keys()) + list(op.get('inputs', {}).keys())
            for f in all_fields:
                norm = self.normalize_field(f)
                if norm not in seen:
                    freq[norm] += 1
                    seen.add(norm)
        # Chuyển sang tần suất tương đối
        self._idf_cache = {k: v / total for k, v in freq.items()}

    def get_idf_weight(self, norm_field):
        """IDF Penalty: Field xuất hiện > 30% APIs là quá phổ biến → downgrade."""
        freq = self._idf_cache.get(norm_field, 0.0)
        if freq > 0.30:
            return 0.25   # Phạt nặng: email xuất hiện khắp nơi
        elif freq > 0.15:
            return 0.55   # Phạt vừa
        return 1.0        # Field hiếm: giữ nguyên

    def get_resource_prefix(self, norm_field):
        """Trích xuất Resource Type từ tên field. VD: 'video id' → 'video', 'order id' → 'order'."""
        tokens = norm_field.split()
        ID_MARKERS = {'id', 'uuid', 'ref', 'no'}
        # Nếu field là 'dạng: <resource> <id_marker>'
        if len(tokens) >= 2 and tokens[-1] in ID_MARKERS:
            return tokens[-2]  # prefix = token đứng trước id_marker
        return None  # Không có prefix xác định

    def resource_type_compatible(self, norm_out, norm_in):
        """Kiểm tra 2 ID-field có cùng Resource Type không. Tránh: video_id → order_id."""
        prefix_out = self.get_resource_prefix(norm_out)
        prefix_in = self.get_resource_prefix(norm_in)
        # Nếu cả 2 đều có prefix xác định nhưng khác nhau → INCOMPATIBLE
        if prefix_out and prefix_in and prefix_out != prefix_in:
            return False
        return True

    def get_value_type_suffix(self, norm_field):
        """Phân loại kiểu giá trị dựa trên token cuối cùng của field."""
        VALUE_TYPE_MAP = {
            # URL / Link types
            'url': 'url_type', 'link': 'url_type', 'path': 'url_type', 'uri': 'url_type',
            # Code / OTP types (short alphanumeric secret)
            'code': 'code_type', 'otp': 'code_type', 'pin': 'code_type',
            # Quantity / Numeric types
            'count': 'numeric_type', 'amount': 'numeric_type',
            'quantity': 'numeric_type', 'price': 'numeric_type',
        }
        last_token = norm_field.split()[-1] if norm_field else ''
        return VALUE_TYPE_MAP.get(last_token, 'generic')

    def value_type_compatible(self, norm_out, norm_in):
        """Kiểm tra 2 field có cùng kiểu giá trị không. Tránh: qr_code_url → coupon_code."""
        type_out = self.get_value_type_suffix(norm_out)
        type_in = self.get_value_type_suffix(norm_in)
        # Nếu cả 2 đều có kiểu xác định (không phải generic) nhưng khác nhau → INCOMPATIBLE
        if type_out != 'generic' and type_in != 'generic' and type_out != type_in:
            return False
        return True

    def calculate_confidence(self, f_out, norm_out, sem_out, f_in, norm_in, sem_in):
        """Tính Confidence Score cho 1 cặp trường."""
        if self.is_noisy(norm_out) or self.is_noisy(norm_in):
            return 0.0, None

        # Stopword Penalty
        weight = self.get_stopword_weight(norm_out) * self.get_stopword_weight(norm_in)

        # IDF Penalty: Phạt field xuất hiện ở quá nhiều APIs
        weight *= self.get_idf_weight(norm_out)

        # Layer 1: Exact Normalized Match
        if norm_out == norm_in:
            # Kiểm tra Resource Type trước khi chấp nhận exact match
            if not self.resource_type_compatible(norm_out, norm_in):
                return 0.0, None
            if not self.value_type_compatible(norm_out, norm_in):
                return 0.0, None
            return 0.95 * weight, "normalized_exact"
            
        # Layer 2: Semantic Inference (Cùng nhóm ngữ nghĩa)
        if sem_out != 'unknown' and sem_out == sem_in:
            # Phải cùng Resource Type và Value Type mới được nối
            if not self.resource_type_compatible(norm_out, norm_in):
                return 0.0, None
            if not self.value_type_compatible(norm_out, norm_in):
                return 0.0, None
            sim_score = self.calculate_jaccard(norm_out, norm_in)
            if sim_score > 0.0:
                bonus = 0.0
                if 'email' in norm_out.split() and 'email' in norm_in.split(): bonus += 0.1
                final_score = min(0.9, 0.75 + (sim_score * 0.15) + bonus)
                return final_score * weight, "semantic"
                
        # Layer 3: Random String Similarity
        sim_score = self.calculate_jaccard(norm_out, norm_in)
        if sim_score >= 0.5:
            return 0.3 * weight, "random_similarity"
            
        return 0.0, None

    def get_directionality_score(self, method_out, method_in):
        """API Role Awareness: Phạt nếu Consumer tạo data dựa trên Read data."""
        if method_out == 'GET' and method_in in ['POST', 'PUT', 'PATCH']:
            return 0.6
        return 1.0

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
        # 0a. Xây dựng IDF Index
        self.build_idf_index()
        print(f"[*] IDF Index: {len(self._idf_cache)} fields unique. Top heavy: "
              f"{[f for f, w in self._idf_cache.items() if w > 0.3]}")

        # 0b. Thu thập field 'unknown' → batch gọi LLM 1 lần duy nhất
        all_unknown = set()
        for op in self.operations:
            for f in list(op.get('outputs', {}).keys()) + list(op.get('inputs', {}).keys()):
                norm = self.normalize_field(f)
                if self.classify_semantic(norm) == 'unknown' and not self.is_noisy(norm):
                    all_unknown.add(norm)

        if all_unknown:
            print(f"[*] LLM đang phân loại {len(all_unknown)} field 'unknown': {sorted(all_unknown)}")
            self.llm_classify_unknown_fields(list(all_unknown))

        # 1. Xây dựng Inverted Semantic Index
        outputs_index = defaultdict(list)
        inputs_index = defaultdict(list)
        
        for op in self.operations:
            method = op.get('method', '').upper()
            op_id = op['id']
            
            # Index Outputs
            if method != 'DELETE': # Xóa bẫy Nghịch lý DELETE
                for f_out in op['outputs'].keys():
                    norm_out = self.normalize_field(f_out)
                    sem_out = self.classify_semantic(norm_out)
                    outputs_index[sem_out].append({
                        'api_id': op_id, 'method': method,
                        'field': f_out, 'norm_field': norm_out, 'sem': sem_out
                    })
                    
            # Index Inputs
            for f_in in op['inputs'].keys():
                norm_in = self.normalize_field(f_in)
                sem_in = self.classify_semantic(norm_in)
                inputs_index[sem_in].append({
                    'api_id': op_id, 'method': method,
                    'field': f_in, 'norm_field': norm_in, 'sem': sem_in
                })
        
        # 2. Xây dựng Graph bằng cách so sánh trong cùng Semantic Bucket
        raw_edges = defaultdict(list) # Lưu tạm edge: (api_out, api_in) -> list(dependencies)
        
        # Xét tất cả các Bucket
        for sem_type in outputs_index.keys():
            out_list = outputs_index[sem_type]
            in_list = inputs_index.get(sem_type, [])
            
            for out_item in out_list:
                for in_item in in_list:
                    if out_item['api_id'] == in_item['api_id']: continue
                    
                    base_score, match_type = self.calculate_confidence(
                        out_item['field'], out_item['norm_field'], out_item['sem'],
                        in_item['field'], in_item['norm_field'], in_item['sem']
                    )
                    
                    if base_score >= 0.5:
                        dir_score = self.get_directionality_score(out_item['method'], in_item['method'])
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
            # Lọc bỏ các cạnh trùng lặp field (do 1 API có thể trả về array object giống nhau)
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
