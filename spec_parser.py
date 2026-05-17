import json
import re

class SpecParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.spec = self._load_spec()
        self.operations = []

    def _load_spec(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[SpecParser] Warning: cannot load spec file: {e}")
            return {}

    def resolve_ref(self, ref_str):
        try:
            parts = ref_str.lstrip('#/').split('/')
            curr = self.spec
            schema_name = parts[-1]
            for p in parts: curr = curr[p]
            return curr, schema_name
        except Exception as e:
            print(f"[SpecParser] Warning: cannot resolve ref {ref_str}: {e}")
            return {}, ""

    def normalize_word(self, word):
        """Mô phỏng Stemming & Case Insensitive theo tài liệu"""
        if not word: return ""
        word = word.lower().strip()
        # Whitelist: các từ kết thúc bằng 's' nhưng KHÔNG phải số nhiều
        STEMMING_EXCEPTIONS = {
            'status', 'access', 'address', 'process', 'progress',
            'success', 'class', 'stress', 'express', 'basis'
        }
        if word not in STEMMING_EXCEPTIONS:
            word = re.sub(r's$', '', word)
        return word

    def apply_id_completion(self, field_name, schema_name, op_name):
        """Kỹ thuật Id Completion quan trọng từ tài liệu Section IV-B"""
        f_norm = field_name.lower()
        if f_norm == "id":
            if schema_name:
                # Nếu thuộc object: pet + id = petId
                return f"{schema_name.lower()}id"
            else:
                # Nếu không thuộc object: lấy tên API (bỏ get/set) + id
                prefix = re.sub(r'^(get|set|update|delete|create)', '', op_name, flags=re.IGNORECASE)
                return f"{prefix.lower()}id"
        return f_norm

    # ── Tập field chung mà không nên dùng tên thô để match dependency ───────
    _GENERIC_FIELDS = {
        'id', 'status', 'type', 'number', 'code', 'name',
        'value', 'count', 'total', 'date', 'time', 'flag'
    }

    @staticmethod
    def _singularize(word: str) -> str:
        """Khử số nhiều đơn giản để dùng làm prefix contextual."""
        if not word:
            return word
        if word.endswith('ies') and len(word) > 4:
            return word[:-3] + 'y'
        if word.endswith('ses') or word.endswith('xes'):
            return word[:-2]
        if word.endswith('s') and len(word) > 3:
            return word[:-1]
        return word

    def extract_props(self, schema, parent_schema="", op_name="",
                      required_fields=None, _json_path="", _root=""):
        """
        Trích xuất field metadata từ schema đệ quy.
        Trả về dict với key là normalized contextual name, value là metadata:
          - original:       tên field gốc trong spec
          - contextual_name: tên được ghép với parent (VD: 'productId', 'orderStatus')
          - json_path:      đường dẫn đầy đủ (VD: 'orders[].product.id')
          - parent:         tên object cha trực tiếp
          - root:           field gốc đầu tiên trong cấu trúc
          - type, format, required, in
        """
        props = {}
        if required_fields is None:
            required_fields = set()
        if not isinstance(schema, dict):
            return props

        if '$ref' in schema:
            resolved, ref_name = self.resolve_ref(schema['$ref'])
            resolved_required = set(resolved.get('required', []))
            ref_path = f"{_json_path}.{ref_name}" if _json_path else ref_name
            root = _root or ref_name
            props.update(self.extract_props(
                resolved, ref_name, op_name, resolved_required, ref_path, root
            ))

        if schema.get('type') == 'object' and 'properties' in schema:
            obj_required = set(schema.get('required', []))
            for k, v in schema['properties'].items():
                field_path = f"{_json_path}.{k}" if _json_path else k
                root       = _root or k
                is_required = k in obj_required or k in required_fields

                # ── Contextual Naming: ghép parent khi field là generic ──────
                k_lower = k.lower()
                if k_lower in self._GENERIC_FIELDS and parent_schema:
                    singular = self._singularize(parent_schema.lower())
                    if k_lower == 'id':
                        # orders[].id → orderId
                        contextual_name = f"{singular}Id"
                    else:
                        # orders[].status → orderStatus
                        contextual_name = f"{singular}{k[0].upper()}{k[1:]}"
                else:
                    # Giữ nguyên apply_id_completion cho field không generic
                    contextual_name = self.apply_id_completion(k, parent_schema, op_name)

                final_name = self.normalize_word(contextual_name)

                if '$ref' in v:
                    props.update(self.extract_props(
                        v, parent_schema, op_name, required_fields, field_path, root
                    ))
                elif v.get('type') == 'object':
                    # Đệ quy vào object con, parent trở thành k
                    props.update(self.extract_props(
                        v, k, op_name, required_fields, field_path, root
                    ))
                else:
                    props[final_name] = {
                        'original':        k,
                        'contextual_name': contextual_name,
                        'json_path':       field_path,
                        'parent':          parent_schema or '',
                        'root':            root,
                        'type':            v.get('type', 'unknown'),
                        'format':          v.get('format', 'unknown'),
                        'required':        is_required,
                        'in':              'body',
                    }

        elif schema.get('type') == 'array' and 'items' in schema:
            # Đệ quy vào items, thêm [] vào path để biểu thị array
            array_path = f"{_json_path}[]" if _json_path else f"{parent_schema}[]"
            root       = _root or parent_schema
            props.update(self.extract_props(
                schema['items'], parent_schema, op_name,
                required_fields, array_path, root
            ))

        return props

    def _infer_resource_nouns(self) -> set:
        """
        Tự động suy ra resource noun từ operationId trong spec.
        Không hardcode domain — hoạt động với bất kỳ Swagger nào.

        VD:  get_orders       → 'order'
             create_vehicle   → 'vehicle'
             validate_coupon  → 'coupon'
             admin_delete_profile_video → 'video'
        """
        VERB_PREFIXES = {
            'get', 'create', 'update', 'delete', 'list', 'add', 'remove',
            'fetch', 'post', 'put', 'patch', 'check', 'validate', 'apply',
            'upload', 'download', 'convert', 'admin', 'login', 'signup',
            'forgot', 'verify', 'change', 'send', 'reset', 'refresh',
            'return', 'cancel', 'accept', 'reject', 'approve', 'enable',
            'disable', 'search', 'filter', 'export', 'import', 'generate'
        }
        GENERIC_WORDS = {
            # API versioning conventions
            'api', 'v1', 'v2', 'v3', 'v2_7',
            # Prepositions / connectors thường xuất hiện trong operationId
            'all', 'by', 'with', 'for', 'and', 'or', 'my',
            # Các từ chỉ trạng thái chung (không phải resource)
            'new', 'old',
            # Từ viết tắt kỹ thuật phổ biến (không phải resource noun)
            'id', 'pic', 'otp', 'qr',
            # Lưu ý: 'token', 'user', 'admin' được bỏ ra vì chúng có thể
            # là resource noun thật sự tùy từng API
        }

        # Hàm khử số nhiều đơn giản
        def depluralize(word: str) -> str:
            if word.endswith('ies') and len(word) > 4:
                return word[:-3] + 'y'
            if word.endswith('ses') or word.endswith('xes'):
                return word[:-2]
            if word.endswith('s') and len(word) > 3:
                return word[:-1]
            return word

        nouns = set()
        if 'paths' not in self.spec:
            return nouns

        for path, methods in self.spec['paths'].items():
            for method, details in methods.items():
                if not isinstance(details, dict):
                    continue
                op_id = details.get('operationId', '')
                # Tách operationId theo snake_case và camelCase
                parts = re.split(r'[_\s]', re.sub(r'([a-z])([A-Z])', r'\1_\2', op_id))
                parts = [p.lower() for p in parts if p]

                for part in parts:
                    if part in VERB_PREFIXES or part in GENERIC_WORDS:
                        continue
                    if len(part) < 3:
                        continue
                    noun = depluralize(part)
                    nouns.add(noun)

        return nouns

    def extract_operations(self):
        if 'paths' not in self.spec: return
        # Tự suy ra resource nouns một lần duy nhất từ spec
        self._resource_nouns = self._infer_resource_nouns()
        for path, methods in self.spec['paths'].items():
            for method, details in methods.items():
                if not isinstance(details, dict): continue
                op_id = details.get('operationId', f"{method.upper()}_{path.replace('/', '_')}")
                inputs, outputs = {}, {}
                req_content_type = "application/json"

                # Trích xuất Inputs
                if 'parameters' in details:
                    for p in details['parameters']:
                        name = p.get('name', '')
                        location = p.get('in', 'query')  # 'path', 'query', 'header'
                        norm_name = self.normalize_word(self.apply_id_completion(name, "", op_id))
                        param_schema = p.get('schema', p)
                        # Path params luôn là required theo OpenAPI spec
                        is_required = p.get('required', False) or location == 'path'
                        inputs[norm_name] = {
                            'original': name,
                            'type': param_schema.get('type', 'unknown'),
                            'format': param_schema.get('format', 'unknown'),
                            'required': is_required,
                            'in': location
                        }
                if 'requestBody' in details:
                    try:
                        rb = details['requestBody']
                        content = rb.get('content', {})
                        schema = None
                        
                        # Chọn content_type theo thứ tự ưu tiên
                        for ct in ['application/json', 'multipart/form-data', 'application/x-www-form-urlencoded', '*/*']:
                            if ct in content:
                                schema = content[ct].get('schema')
                                req_content_type = ct
                                break
                                
                        if schema:
                            top_required = set()
                            if '$ref' in schema:
                                resolved, _ = self.resolve_ref(schema['$ref'])
                                top_required = set(resolved.get('required', []))
                            else:
                                top_required = set(schema.get('required', []))
                            inputs.update(self.extract_props(schema, op_name=op_id, required_fields=top_required))
                    except Exception as e:
                        print(f"[SpecParser] Warning: cannot parse requestBody for {op_id}: {e}")

                # Trích xuất Outputs: hợp nhất tất cả 2xx response schemas
                # (200=GET, 201=POST create, 202=accepted) để không bỏ sót API tạo mới
                if 'responses' in details:
                    for code in ['200', '201', '202']:
                        if code in details['responses']:
                            try:
                                content = details['responses'][code].get('content', {})
                                resp_schema = None
                                for ct in ['application/json', '*/*']:
                                    if ct in content:
                                        resp_schema = content[ct].get('schema')
                                        break
                                
                                if resp_schema:
                                    root_hint = ''
                                    if resp_schema.get('type') == 'array':
                                        root_hint = re.sub(
                                            r'^(get|list|fetch|search)_?', '', op_id, flags=re.I
                                        ).lower()
                                    outputs.update(self.extract_props(
                                        resp_schema,
                                        parent_schema=root_hint,
                                        op_name=op_id
                                    ))
                            except Exception as e:
                                print(f"[SpecParser] Warning: cannot parse response {code} for {op_id}: {e}")

                # ── Fix 1: Passthrough outputs cho API có output rỗng ─────────────────
                # API trả về binary/non-JSON → phản chiếu path/query param làm output.
                if not outputs and inputs:
                    for field_name, meta in inputs.items():
                        if not isinstance(meta, dict):
                            continue
                        location = meta.get('in', 'body')
                        if location in ('path', 'query'):
                            orig = meta.get('original', field_name)
                            outputs[field_name] = {
                                'original':        orig,
                                'contextual_name': orig,
                                'json_path':       orig,
                                'parent':          '',
                                'root':            orig,
                                'type':            meta.get('type', 'unknown'),
                                'format':          meta.get('format', 'unknown'),
                                '_passthrough':    True
                            }

                # ── Fix 2: Resource Object Expansion (generic — tự học từ spec) ────────
                # Khi output là field tên resource noun nhưng không có sub-properties,
                # suy ra implied ID field. Resource nouns được tự suy ra từ operationId.
                expanded = {}
                for field_name, meta in list(outputs.items()):
                    if not isinstance(meta, dict):
                        continue
                    norm_f = re.sub(r'[-_\s]', '', field_name).lower()
                    if norm_f in self._resource_nouns:
                        implied_id = f"{norm_f}id"
                        if implied_id not in outputs:
                            singular = self._singularize(field_name)
                            cname    = f"{singular}Id"
                            expanded[implied_id] = {
                                'original':        f"{field_name}Id",
                                'contextual_name': cname,
                                'json_path':       f"{field_name}.id",
                                'parent':          field_name,
                                'root':            field_name,
                                'type':            'string',
                                'format':          'unknown',
                                '_inferred':       True
                            }
                outputs.update(expanded)

                self.operations.append({
                    'id': op_id, 
                    'method': method.upper(), 
                    'path': path, 
                    'inputs': inputs, 
                    'outputs': outputs,
                    'content_type': req_content_type
                })

        
        return self.operations
