class DependencyGraphBuilder:
    def __init__(self, operations):
        self.operations = operations
        self.adjacency_list = {op['id']: [] for op in self.operations}

    def build_scientific_odg(self, output_file="ODG_Scientific_Final.dot"):
        """Xây dựng đồ thị theo quan hệ n1 -> n2 (Dependency Inference) và trả về Adjacency List"""
        dot = "digraph G {\n    rankdir=LR;\n"
        dot += "    node [shape=box, style=filled, color=\"#E3F2FD\", fontname=\"Arial\"];\n"
        dot += "    edge [fontname=\"Arial\", fontsize=9];\n\n"

        # Khai báo node
        for op in self.operations:
            dot += f'    "{op["id"]}";\n'

        edges_count = 0
        for n1 in self.operations: # Nguồn dữ liệu (output)
            for n2 in self.operations: # Đích tiêu thụ (input)
                if n1['id'] == n2['id']: continue
                
                # Tìm trường chung (common field)
                common_fields = set(n1['outputs'].keys()) & set(n2['inputs'].keys())
                
                # Loại bỏ các trường quá chung chung gây "chằng chịt" (như message, status)
                noise = {'message', 'status', 'success', 'error'}
                common_fields = common_fields - noise

                if common_fields:
                    # Theo tài liệu: Edge v = n1 -> n2 (n1 cung cấp cho n2)
                    label = ", ".join([n1['outputs'][f] for f in common_fields])
                    dot += f'    "{n1["id"]}" -> "{n2["id"]}" [label="{label}"];\n'
                    edges_count += 1
                    
                    # Lưu vào danh sách kề (Adjacency List) để duyệt đồ thị sau này
                    self.adjacency_list[n1['id']].append({
                        'to': n2['id'],
                        'fields': list(common_fields),
                        'label': label
                    })

        dot += "}\n"
        with open(output_file, 'w', encoding='utf-8') as f: f.write(dot)
        print(f"[*] Đã tạo đồ thị ODG với {edges_count} cạnh.")
        
        return self.adjacency_list
