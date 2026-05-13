import re
from collections import defaultdict
from llm_planner import LLMPlanner

class RuleInferenceLayer:
    """
    Cung cấp các luật (Rules) để phán đoán sự tương thích giữa 2 API.
    Được tách ra từ DependencyGraphBuilder để dễ bảo trì và test.
    """
    def __init__(self, planner: LLMPlanner, operations: list):
        self.planner = planner
        self.operations = operations
        self._idf_cache = {}
        self.build_idf_index()

    def normalize_field(self, field_name):
        s = re.sub(r'([a-z])([A-Z])', r'\1 \2', field_name)
        s = re.sub(r'[-_\.]', ' ', s)
        return ' '.join(s.lower().split())

    def build_idf_index(self):
        """Xây dựng IDF Index: Đếm tần suất xuất hiện của mỗi field trên toàn bộ API (inputs + outputs)."""
        freq = defaultdict(int)
        total = len(self.operations)
        for op in self.operations:
            seen = set()
            all_fields = list(op.get('outputs', {}).keys()) + list(op.get('inputs', {}).keys())
            for f in all_fields:
                norm = self.normalize_field(f)
                if norm not in seen:
                    freq[norm] += 1
                    seen.add(norm)
        if total > 0:
            self._idf_cache = {k: v / total for k, v in freq.items()}

    def get_idf_weight(self, norm_field):
        """IDF Penalty: Field xuất hiện > 30% APIs là quá phổ biến → downgrade."""
        freq = self._idf_cache.get(norm_field, 0.0)
        if freq > 0.30: return 0.25
        elif freq > 0.15: return 0.55
        return 1.0

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
            return 0.4
        return 1.0

    def classify_semantic(self, norm_field):
        """Phân loại ngữ nghĩa: Rule-based trước, LLM cache làm fallback."""
        tokens = norm_field.split()
        if any(kw in tokens for kw in ['id', 'uuid', 'email', 'phone', 'no', 'ref', 'vin', 'member', 'customer', 'subscriber', 'account', 'user']):
            return 'identity'
        if any(kw in tokens for kw in ['token', 'session', 'role', 'cookie', 'hash', 'key', 'code', 'status', 'state']):
            return 'auth/workflow'
        if any(kw in tokens for kw in ['balance', 'credit', 'amount', 'price', 'fee']):
            return 'finance'

        # LLM Fallback: Lấy từ cache
        cached = self.planner.get_semantic_cache(norm_field)
        if cached:
            return cached
        return 'unknown'

    def calculate_jaccard(self, norm_out, norm_in):
        """Tính Jaccard Similarity cơ bản."""
        set1 = set(norm_out.split())
        set2 = set(norm_in.split())
        if not set1 or not set2: return 0.0
        return float(len(set1.intersection(set2))) / len(set1.union(set2))

    def get_resource_prefix(self, norm_field):
        """Trích xuất Resource Type từ tên field. VD: 'video id' → 'video'."""
        tokens = norm_field.split()
        ID_MARKERS = {'id', 'uuid', 'ref', 'no'}
        if len(tokens) >= 2 and tokens[-1] in ID_MARKERS:
            return tokens[-2]
        return None

    def resource_type_compatible(self, norm_out, norm_in):
        """Kiểm tra 2 ID-field có cùng Resource Type không."""
        prefix_out = self.get_resource_prefix(norm_out)
        prefix_in = self.get_resource_prefix(norm_in)
        if prefix_out and prefix_in and prefix_out != prefix_in:
            return False
        return True

    def get_value_type_suffix(self, norm_field):
        """Phân loại kiểu giá trị dựa trên token cuối cùng của field."""
        VALUE_TYPE_MAP = {
            'url': 'url_type', 'link': 'url_type', 'path': 'url_type', 'uri': 'url_type',
            'code': 'code_type', 'otp': 'code_type', 'pin': 'code_type',
            'count': 'numeric_type', 'amount': 'numeric_type',
            'quantity': 'numeric_type', 'price': 'numeric_type',
        }
        last_token = norm_field.split()[-1] if norm_field else ''
        return VALUE_TYPE_MAP.get(last_token, 'generic')

    def value_type_compatible(self, norm_out, norm_in):
        """Kiểm tra 2 field có cùng kiểu giá trị không."""
        type_out = self.get_value_type_suffix(norm_out)
        type_in = self.get_value_type_suffix(norm_in)
        if type_out != 'generic' and type_in != 'generic' and type_out != type_in:
            return False
        return True

    def calculate_confidence(self, f_out, norm_out, sem_out, fmt_out,
                             f_in,  norm_in,  sem_in,  fmt_in):
        """Tính Confidence Score cho 1 cặp trường (Hybrid: Rule + Format + LLM Cluster)."""
        if self.is_noisy(norm_out) or self.is_noisy(norm_in):
            return 0.0, None

        # FORMAT GUARD (Hard Filter)
        if (fmt_out != 'unknown' and fmt_in != 'unknown' and fmt_out != fmt_in):
            return 0.0, None

        # Penalties
        weight = self.get_stopword_weight(norm_out) * self.get_stopword_weight(norm_in)
        weight *= self.get_idf_weight(norm_out)

        # LAYER 1: Exact Normalized Match
        if norm_out == norm_in:
            if not self.resource_type_compatible(norm_out, norm_in): return 0.0, None
            if not self.value_type_compatible(norm_out, norm_in):    return 0.0, None
            return 0.95 * weight, "normalized_exact"

        # LAYER 2: Semantic Inference
        if sem_out != 'unknown' and sem_out == sem_in:
            if not self.resource_type_compatible(norm_out, norm_in): return 0.0, None
            if not self.value_type_compatible(norm_out, norm_in):    return 0.0, None

            # Layer 2a: LLM Identity Clustering
            if sem_out == 'identity':
                cluster_map = self.planner.get_cluster_map()
                if cluster_map:
                    cid_out = cluster_map.get(norm_out)
                    cid_in  = cluster_map.get(norm_in)
                    if cid_out is not None and cid_in is not None and cid_out == cid_in:
                        return 0.85 * weight, "llm_identity_cluster"

            # Layer 2b: Jaccard Semantic Match
            sim_score = self.calculate_jaccard(norm_out, norm_in)
            if sim_score > 0.0:
                bonus = 0.1 if ('email' in norm_out.split() and 'email' in norm_in.split()) else 0.0
                final_score = min(0.9, 0.75 + (sim_score * 0.15) + bonus)
                return final_score * weight, "semantic"

        # LAYER 3: Random String Similarity
        sim_score = self.calculate_jaccard(norm_out, norm_in)
        if sim_score >= 0.5:
            return 0.3 * weight, "random_similarity"

        return 0.0, None

    def get_directionality_score(self, method_out, method_in):
        """API Role Awareness: Phạt nếu Consumer tạo data dựa trên Read data."""
        if method_out == 'GET' and method_in in ['POST', 'PUT', 'PATCH']:
            return 0.6
        return 1.0

    def get_idf_cache(self):
        return self._idf_cache
