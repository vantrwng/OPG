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

    def extract_props(self, schema, parent_schema="", op_name=""):
        props = {}
        if not isinstance(schema, dict): return props
        if '$ref' in schema:
            resolved, ref_name = self.resolve_ref(schema['$ref'])
            props.update(self.extract_props(resolved, ref_name, op_name))
        
        if schema.get('type') == 'object' and 'properties' in schema:
            for k, v in schema['properties'].items():
                # Thực hiện Id Completion & Normalization
                completed_name = self.apply_id_completion(k, parent_schema, op_name)
                final_name = self.normalize_word(completed_name)
                
                if '$ref' in v:
                    # $ref: để resolve_ref tự lấy tên schema đúng
                    props.update(self.extract_props(v, parent_schema, op_name))
                elif v.get('type') == 'object':
                    # Inline object: dùng tên field hiện tại (k) làm parent mới
                    props.update(self.extract_props(v, k, op_name))
                else:
                    # Lưu metadata đầy đủ: tên gốc + type + format
                    props[final_name] = {
                        'original': k,
                        'type': v.get('type', 'unknown'),
                        'format': v.get('format', 'unknown')
                    }
        elif schema.get('type') == 'array' and 'items' in schema:
            props.update(self.extract_props(schema['items'], parent_schema, op_name))
        return props

    def extract_operations(self):
        if 'paths' not in self.spec: return
        for path, methods in self.spec['paths'].items():
            for method, details in methods.items():
                if not isinstance(details, dict): continue
                op_id = details.get('operationId', f"{method.upper()}_{path.replace('/', '_')}")
                inputs, outputs = {}, {}

                # Trích xuất Inputs
                if 'parameters' in details:
                    for p in details['parameters']:
                        name = p.get('name', '')
                        norm_name = self.normalize_word(self.apply_id_completion(name, "", op_id))
                        # Lấy type/format từ schema của parameter (OpenAPI 3.x) hoặc trực tiếp (2.x)
                        param_schema = p.get('schema', p)
                        inputs[norm_name] = {
                            'original': name,
                            'type': param_schema.get('type', 'unknown'),
                            'format': param_schema.get('format', 'unknown')
                        }
                if 'requestBody' in details:
                    try:
                        schema = details['requestBody']['content']['application/json']['schema']
                        inputs.update(self.extract_props(schema, op_name=op_id))
                    except Exception as e:
                        print(f"[SpecParser] Warning: cannot parse requestBody for {op_id}: {e}")

                # Trích xuất Outputs: hợp nhất tất cả 2xx response schemas
                # (200=GET, 201=POST create, 202=accepted) để không bỏ sót API tạo mới
                if 'responses' in details:
                    for code in ['200', '201', '202']:
                        if code in details['responses']:
                            try:
                                schema = details['responses'][code]['content']['application/json']['schema']
                                outputs.update(self.extract_props(schema, op_name=op_id))
                            except Exception as e:
                                print(f"[SpecParser] Warning: cannot parse response {code} for {op_id}: {e}")
                
                self.operations.append({'id': op_id, 'method': method.upper(), 'path': path, 'inputs': inputs, 'outputs': outputs})
        
        return self.operations
