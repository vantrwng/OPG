import copy
import json
import re

class SpecParser:
    _HTTP_METHODS = {
        'get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'
    }

    def __init__(self, file_path, overlay_path=None):
        self.file_path = file_path
        self.overlay_path = overlay_path
        self.parse_errors = []
        self.spec = self._load_spec()
        self.operations = []

    def _load_spec(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                spec = json.load(f)
            if self.overlay_path:
                with open(self.overlay_path, 'r', encoding='utf-8') as f:
                    overlay = json.load(f)
                if not isinstance(overlay, dict):
                    raise ValueError("OpenAPI overlay must be a JSON object")
                # Overlays intentionally replace/add complete path items. This
                # keeps generated vendor specs immutable while allowing hidden
                # lifecycle endpoints to be described for the test harness.
                for key, value in overlay.items():
                    if key == "paths" and isinstance(value, dict):
                        spec.setdefault("paths", {}).update(copy.deepcopy(value))
                    elif key == "x-bola":
                        spec[key] = copy.deepcopy(value)
                    elif key == "components" and isinstance(value, dict):
                        spec.setdefault("components", {}).update(copy.deepcopy(value))
                    else:
                        spec[key] = copy.deepcopy(value)
            return spec
        except Exception as e:
            self.parse_errors.append({
                "stage": "generation_failed", "scope": "spec",
                "reason": f"{type(e).__name__}: {e}",
            })
            print(f"[SpecParser] Warning: cannot load spec file: {e}")
            return {}

    def _security_metadata(self, raw_security, source="none"):
        """Normalize OpenAPI security without interpreting absence as a defect."""
        schemes = []
        entries = raw_security if isinstance(raw_security, list) else [raw_security]
        for entry in entries:
            if isinstance(entry, dict):
                schemes.extend(str(name) for name in entry)
        definitions = (
            self.spec.get("components", {}).get("securitySchemes", {})
            or self.spec.get("securityDefinitions", {})
        )
        transports = []
        for scheme_name in sorted(set(schemes)):
            definition = definitions.get(scheme_name, {})
            scheme_type = str(definition.get("type", "")).lower()
            location = str(definition.get("in", "")).lower()
            if scheme_type == "apikey" and location in {"cookie", "header", "query"}:
                transports.append({
                    "scheme_name": scheme_name,
                    "kind": location,
                    "name": definition.get("name", scheme_name),
                    "prefix": "",
                    "source": "openapi",
                })
            elif scheme_type == "http" and str(definition.get("scheme", "")).lower() == "bearer":
                transports.append({
                    "scheme_name": scheme_name,
                    "kind": "header",
                    "name": "Authorization",
                    "prefix": "Bearer",
                    "source": "openapi",
                })
        return {
            "security_required": bool(raw_security),
            "security_schemes": sorted(set(schemes)),
            "security_source": source,
            "declared_auth_transports": transports,
        }

    @staticmethod
    def _semantic_features(op_id, method, path, inputs, outputs, details):
        """Extract generic defensive-classification features from an operation."""
        selector_fields = []
        for name, meta in (inputs or {}).items():
            if not isinstance(meta, dict) or meta.get("in") != "path":
                continue
            selector_fields.append(meta.get("original", name))

        sensitive_re = re.compile(
            r"password|passwd|secret|token|credential|api[_-]?key|ssn|email|"
            r"phone|admin|permission|role|private|balance|credit",
            re.I,
        )
        sensitive_fields = set()

        def _collect_sensitive(name, schema):
            schema = schema if isinstance(schema, dict) else {}
            original = str(schema.get("original", name))
            if sensitive_re.search(original):
                sensitive_fields.add(original)
            for child_name, child_schema in (schema.get("properties", {}) or {}).items():
                _collect_sensitive(child_name, child_schema)
            items = schema.get("items", {}) or {}
            if isinstance(items, dict):
                for child_name, child_schema in (items.get("properties", {}) or {}).items():
                    _collect_sensitive(child_name, child_schema)
                nested_items = items.get("items")
                if isinstance(nested_items, dict):
                    _collect_sensitive(name, nested_items)

        for name, meta in (outputs or {}).items():
            meta = meta if isinstance(meta, dict) else {}
            # Request post-conditions are dependency evidence, not response data.
            if meta.get("_request_passthrough") or meta.get("_passthrough"):
                continue
            _collect_sensitive(name, meta)

        text = " ".join((
            str(op_id), str(path), str(details.get("summary", "")),
            str(details.get("description", "")),
            " ".join(str(tag) for tag in details.get("tags", [])),
        )).lower()
        privileged_re = re.compile(
            r"(^|[^a-z])(admin|debug|internal|system|database|db|maintenance|"
            r"populate|seed|initialize|migrate|reset|purge|drop)([^a-z]|$)",
            re.I,
        )
        destructive_re = re.compile(
            r"(^|[^a-z])(populate|seed|initialize|migrate|reset|purge|drop|"
            r"truncate|rebuild|createdb)([^a-z]|$)",
            re.I,
        )
        return {
            "resource_selectors": selector_fields,
            "sensitive_response_fields": sorted(sensitive_fields),
            "privileged_function_hint": bool(privileged_re.search(text)),
            "potentially_destructive": bool(destructive_re.search(text)),
            "state_changing_get": method.upper() == "GET" and bool(destructive_re.search(text)),
        }

    def resolve_ref(self, ref_str):
        try:
            parts = ref_str.lstrip('#/').split('/')
            curr = self.spec
            schema_name = parts[-1]
            for p in parts: curr = curr[p]
            return curr, schema_name
        except Exception as e:
            self.parse_errors.append({
                "stage": "generation_failed", "scope": str(ref_str),
                "reason": f"{type(e).__name__}: {e}",
            })
            print(f"[SpecParser] Warning: cannot resolve ref {ref_str}: {e}")
            return {}, ""

    def get_bola_config(self):
        """Return optional dataset-specific BOLA hints from top-level OpenAPI."""
        config = self.spec.get("x-bola", {})
        return dict(config) if isinstance(config, dict) else {}

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
            # A component name describes the schema; it is not a key in the
            # serialized JSON document.  For example, `data: $ref: Memo`
            # produces `data.id` on the wire, not `data.Memo.id`.
            ref_path = _json_path
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
                    field_format = v.get('format', 'unknown')
                    props[final_name] = {
                        'original':        k,
                        'contextual_name': contextual_name,
                        'json_path':       field_path,
                        'parent':          parent_schema or '',
                        'root':            root,
                        'type':            v.get('type', 'unknown'),
                        'items':           dict(v.get('items', {})) if isinstance(v.get('items'), dict) else {},
                        'format':          field_format,
                        'enum':            list(v.get('enum', []) or []),
                        'default':         v.get('default'),
                        'is_file':         field_format in ('binary', 'byte'),
                        'content_media_type': v.get('contentMediaType', ''),
                        'required':        is_required,
                        'in':              'body',
                        **{
                            key: v[key] for key in (
                                'minimum', 'maximum', 'exclusiveMinimum',
                                'exclusiveMaximum', 'multipleOf', 'minLength',
                                'maxLength', 'pattern', 'minItems', 'maxItems',
                                'uniqueItems', 'nullable', 'readOnly', 'writeOnly',
                            ) if key in v
                        },
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
                if method.lower() not in self._HTTP_METHODS or not isinstance(details, dict):
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
                if method.lower() not in self._HTTP_METHODS or not isinstance(details, dict):
                    continue
                op_id = details.get('operationId', f"{method.upper()}_{path.replace('/', '_')}")
                inputs, outputs = {}, {}
                response_content_types = set()
                response_body_statuses = set()
                req_content_type = "application/json"
                expected_success_statuses = []
                for response_code in (details.get('responses', {}) or {}):
                    code_text = str(response_code).upper()
                    if (code_text.isdigit() and 200 <= int(code_text) < 300) or code_text == '2XX':
                        expected_success_statuses.append(code_text)

                # Path-item parameters apply to every operation. Operation-level
                # entries override a path-level parameter with the same (name, in).
                merged_parameters = {}
                for parameter in list(methods.get('parameters', []) or []) + list(details.get('parameters', []) or []):
                    p = parameter
                    if isinstance(p, dict) and '$ref' in p:
                        p, _ = self.resolve_ref(p['$ref'])
                    if not isinstance(p, dict):
                        continue
                    identity = (str(p.get('name', '')), str(p.get('in', 'query')))
                    merged_parameters[identity] = p
                if merged_parameters:
                    for p in merged_parameters.values():
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
                            'enum': list(param_schema.get('enum', []) or []),
                            'default': param_schema.get('default'),
                            'required': is_required,
                            'in': location,
                            **{
                                key: param_schema[key] for key in (
                                    'minimum', 'maximum', 'exclusiveMinimum',
                                    'exclusiveMaximum', 'multipleOf', 'minLength',
                                    'maxLength', 'pattern', 'minItems', 'maxItems',
                                    'uniqueItems', 'nullable',
                                ) if key in param_schema
                            },
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
                        if schema is None and content:
                            req_content_type, media = next(iter(content.items()))
                            schema = media.get('schema')
                                
                        if schema:
                            top_required = set()
                            if '$ref' in schema:
                                resolved, _ = self.resolve_ref(schema['$ref'])
                                top_required = set(resolved.get('required', []))
                            else:
                                top_required = set(schema.get('required', []))
                            if schema.get('type') == 'string' and schema.get('format') in ('binary', 'byte'):
                                inputs['body'] = {
                                    'original': 'body', 'type': 'string',
                                    'format': schema.get('format'), 'required': rb.get('required', False),
                                    'in': 'body', 'is_file': True,
                                    'content_type': req_content_type,
                                }
                            else:
                                inputs.update(self.extract_props(schema, op_name=op_id, required_fields=top_required))
                                encoding = content.get(req_content_type, {}).get('encoding', {})
                                for field_name, meta in inputs.items():
                                    if not isinstance(meta, dict) or not meta.get('is_file'):
                                        continue
                                    original = meta.get('original', field_name)
                                    encoded = encoding.get(original, {}) if isinstance(encoding, dict) else {}
                                    meta['content_type'] = encoded.get('contentType') or meta.get('content_media_type', '')
                    except Exception as e:
                        self.parse_errors.append({
                            "stage": "generation_failed", "scope": op_id,
                            "reason": f"requestBody: {type(e).__name__}: {e}",
                        })
                        print(f"[SpecParser] Warning: cannot parse requestBody for {op_id}: {e}")

                # Merge every declared 2xx response schema, including wildcard 2XX.
                if 'responses' in details:
                    for code, response_details in (details['responses'] or {}).items():
                        code_text = str(code).upper()
                        is_success = (
                            (code_text.isdigit() and 200 <= int(code_text) < 300)
                            or code_text == '2XX'
                        )
                        if is_success:
                            try:
                                if isinstance(response_details, dict) and '$ref' in response_details:
                                    response_details, _ = self.resolve_ref(response_details['$ref'])
                                response_details = response_details if isinstance(response_details, dict) else {}
                                content = response_details.get('content', {}) or {}
                                if content:
                                    response_body_statuses.add(code_text)
                                response_content_types.update(str(ct) for ct in content)
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
                                self.parse_errors.append({
                                    "stage": "generation_failed", "scope": op_id,
                                    "reason": f"response {code_text}: {type(e).__name__}: {e}",
                                })
                                print(f"[SpecParser] Warning: cannot parse response {code_text} for {op_id}: {e}")

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

                # A successful create/add API may return only status/message.
                # Its request fields are nevertheless valid post-conditions and
                # can provide dependencies to downstream read/update/delete APIs.
                noise_outputs = {'status', 'message', 'success', 'error', 'detail'}
                meaningful_outputs = {
                    re.sub(r'[-_.\s]', '', name).lower()
                    for name in outputs
                    if re.sub(r'[-_.\s]', '', name).lower() not in noise_outputs
                }
                mutation_like = method.upper() in ('POST', 'PUT', 'PATCH')
                if mutation_like and not meaningful_outputs:
                    for field_name, meta in inputs.items():
                        if not isinstance(meta, dict):
                            continue
                        location = meta.get('in', 'body')
                        if location not in ('body', 'path', 'query'):
                            continue
                        orig = meta.get('original', field_name)
                        outputs.setdefault(field_name, {
                            'original':        orig,
                            'contextual_name': orig,
                            'json_path':       orig,
                            'parent':          '',
                            'root':            orig,
                            'type':            meta.get('type', 'unknown'),
                            'format':          meta.get('format', 'unknown'),
                            '_request_passthrough': True,
                        })

                # ── Fix 2: Resource Object Expansion (generic — tự học từ spec) ────────
                # Khi output là field tên resource noun nhưng không có sub-properties,
                # suy ra implied ID field. Resource nouns được tự suy ra từ operationId.
                expanded = {}
                for field_name, meta in list(outputs.items()):
                    if not isinstance(meta, dict):
                        continue
                    if meta.get('_request_passthrough') or meta.get('_passthrough'):
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

                if 'security' in details:
                    security_meta = self._security_metadata(
                        details.get('security'), source='operation'
                    )
                elif 'security' in self.spec:
                    security_meta = self._security_metadata(
                        self.spec.get('security'), source='global'
                    )
                else:
                    security_meta = self._security_metadata(None, source='none')

                semantic_meta = self._semantic_features(
                    op_id, method, path, inputs, outputs, details
                )

                self.operations.append({
                    'id': op_id, 
                    'method': method.upper(), 
                    'path': path, 
                    'inputs': inputs, 
                    'outputs': outputs,
                    'content_type': req_content_type,
                    'expected_success_statuses': expected_success_statuses,
                    'response_content_types': sorted(response_content_types),
                    'response_body_statuses': sorted(response_body_statuses),
                    'tags': list(details.get('tags', []) or []),
                    'summary': details.get('summary', ''),
                    'description': details.get('description', ''),
                    **security_meta,
                    **semantic_meta,
                })

        
        return self.operations
