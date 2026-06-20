import sys, io
import logging

# Ensure UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from spec_parser import SpecParser
from graph_builder import DependencyGraphBuilder
from rule_inference_layer import RuleInferenceLayer
from llm_planner import LLMPlanner

def debug_print_api_relationships(spec_file="capital.json"):
    print(f"[*] Đang phân tích OpenAPI spec từ file: {spec_file}...")
    parser = SpecParser(spec_file)
    operations = parser.extract_operations()
    if not operations:
        print("[-] Không có operations nào được tìm thấy!")
        return

    print("[*] Đang khởi tạo các công cụ xử lý đồ thị (Planner, Rule Layer, Graph Builder)...")
    planner = LLMPlanner()
    rule_layer = RuleInferenceLayer(planner, operations)
    graph_builder = DependencyGraphBuilder(operations, rule_layer, planner)
    
    print("[*] Đang xây dựng Dependency Graph...")
    # Không cần file dot để vẽ, nhưng hàm build_scientific_odg vẫn yêu cầu param này, ta cứ để tên temp
    adjacency_list = graph_builder.build_scientific_odg(output_file="temp_debug.dot")

    print("\n" + "="*80)
    print(f"{'MỐI QUAN HỆ GIỮA CÁC API (API DEPENDENCIES)':^80}")
    print("="*80)

    total_edges = 0
    for api_out, edges in adjacency_list.items():
        if not edges:
            continue
        
        print(f"\n[📦 PROVIDER] {api_out}")
        for edge in edges:
            to_api = edge['to']
            conf = edge['max_confidence']
            etype = edge.get('edge_type', 'unknown')
            
            print(f"  └──> [🎯 CONSUMER] {to_api}  |  Loại cạnh: {etype.upper()}  |  Độ tin cậy tối đa: {conf:.2f}")
            
            for idx, dep in enumerate(edge.get('dependencies', []), start=1):
                prod = dep.get('producer_field', '?')
                cons = dep.get('consumer_field', '?')
                imp = dep.get('importance', '?')
                dconf = dep.get('confidence', 0)
                match = dep.get('match_type', '?')
                
                print(f"         {idx}. Field cung cấp: {prod:<20} --> Nhận: {cons:<20}")
                print(f"            (Độ quan trọng: {imp:<10} | Conf: {dconf:.2f} | Match: {match})")
            total_edges += 1

    print("\n" + "="*80)
    print(f"Tổng số mối quan hệ (edges) tìm được: {total_edges}")
    print("="*80)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Debug print API relationships")
    parser.add_argument("--spec", type=str, default="capital.json", help="Path to OpenAPI spec file")
    args = parser.parse_args()
    
    debug_print_api_relationships(args.spec)
