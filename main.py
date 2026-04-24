import json
import re

class ODGScientificAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.spec = self._load_spec()
        self.operations = []

    def _load_spec(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except: return {}

    def resolve_ref(self, ref_str):
        try:
            parts = ref_str.lstrip('#/').split('/')
            curr = self.spec
            schema_name = parts[-1]
            for p in parts: curr = curr[p]
            return curr, schema_name
        except: return {}, ""

    def normalize_word(self, word):
        """Mô phỏng Stemming & Case Insensitive theo tài liệu"""
        if not word: return ""
        word = word.lower().strip()
        # Loại bỏ các ký tự đặc biệt và hậu tố 's' (stemming đơn giản)
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
                
                if v.get('type') == 'object' or '$ref' in v:
                    props.update(self.extract_props(v, parent_schema, op_name))
                else:
                    props[final_name] = k # Lưu lại tên gốc để làm nhãn (label)
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
                        inputs[norm_name] = name
                if 'requestBody' in details:
                    try:
                        schema = details['requestBody']['content']['application/json']['schema']
                        inputs.update(self.extract_props(schema, op_name=op_id))
                    except: pass

                # Trích xuất Outputs (n1 trong tài liệu)
                if 'responses' in details and '200' in details['responses']:
                    try:
                        schema = details['responses']['200']['content']['application/json']['schema']
                        outputs.update(self.extract_props(schema, op_name=op_id))
                    except: pass
                
                self.operations.append({'id': op_id, 'inputs': inputs, 'outputs': outputs})

    def build_scientific_odg(self, output_file="ODG_Scientific_Final.dot"):
        """Xây dựng đồ thị theo quan hệ n1 -> n2 (Dependency Inference)"""
        dot = "digraph G {\n    rankdir=LR;\n"
        dot += "    node [shape=box, style=filled, color=\"#E3F2FD\", fontname=\"Arial\"];\n"
        dot += "    edge [fontname=\"Arial\", fontsize=9];\n\n"

        # Khai báo node
        for op in self.operations:
            dot += f'    "{op["id"]}";\n'

        edges = 0
        for n1 in self.operations: # Nguồn dữ liệu (output)
            for n2 in self.operations: # Đích tiêu thụ (input)
                if n1['id'] == n2['id']: continue
                
                # Tìm trường chung (common field)
                common_fields = set(n1['outputs'].keys()) & set(n2['inputs'].keys())
                
                # Loại bỏ các trường quá chung chung gây "chằng chịt" (như message, status)
                noise = {'message', 'status', 'success', 'error'}
                common_fields = common_fields - noise

                if common_fields:
                    # Theo tài liệu: Edge v = n2 -> n1 (n1 cung cấp cho n2)
                    label = ", ".join([n1['outputs'][f] for f in common_fields])
                    dot += f'    "{n1["id"]}" -> "{n2["id"]}" [label="{label}"];\n'
                    edges += 1

        dot += "}\n"
        with open(output_file, 'w', encoding='utf-8') as f: f.write(dot)
        print(f"[*] Đã tạo ODG chuẩn khoa học với {edges} cạnh dựa trên Dependency Inference.")

if __name__ == "__main__":
    analyzer = ODGScientificAnalyzer('crapi-openapi-spec.json')
    analyzer.extract_operations()
    analyzer.build_scientific_odg()