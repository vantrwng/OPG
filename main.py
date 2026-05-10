from spec_parser import SpecParser
from graph_builder import DependencyGraphBuilder
from hybrid_fuzzer import HybridBeamFuzzer

def main():
    print("=== Hệ thống Phân tích và Xây dựng Chiến lược Kiểm thử API ===")
    
    # 1. Khởi tạo và phân tích OpenAPI Spec
    print("\n[1] Đang phân tích OpenAPI Specification...")
    spec_file = 'crapi-openapi-spec.json'
    parser = SpecParser(spec_file)
    operations = parser.extract_operations()
    if not operations:
        print("[-] Không tìm thấy operations nào hoặc lỗi khi đọc spec.")
        return
    print(f"[*] Đã trích xuất {len(operations)} operations từ spec.")

    # 2. Xây dựng Đồ thị phụ thuộc (ODG)
    print("\n[2] Đang xây dựng Đồ thị Phụ thuộc (ODG)...")
    graph_builder = DependencyGraphBuilder(operations)
    adjacency_list = graph_builder.build_scientific_odg(output_file="ODG_Scientific_Final.dot")

    # 3. Chạy mô phỏng Hybrid BFS + Beam Search Fuzzer (Dynamic Analysis)
    print("\n[3] Đang khởi chạy Hybrid BFS + Beam Search Fuzzer (Stateful Fuzzing)...")
    dynamic_fuzzer = HybridBeamFuzzer(operations, adjacency_list, beam_width=5)
    
    # Chạy Fuzzer lên tới độ sâu 10
    best_chains = dynamic_fuzzer.run_fuzzer(max_depth=10)
    
    # Xuất ra kết quả
    dynamic_fuzzer.export_results(best_chains, output_file="beam_strategies.json")
    
    print("\n=== Hoàn thành Hệ thống Phân tích Tĩnh và Động! ===")

if __name__ == "__main__":
    main()