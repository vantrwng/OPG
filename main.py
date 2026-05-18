import sys
import io
import logging

# Đảm bảo in tiếng Việt ra console trên Windows không bị lỗi UnicodeEncodeError
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Cấu hình logging để hiển thị log lên terminal
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

import os
from dotenv import load_dotenv
load_dotenv()

from spec_parser import SpecParser
from graph_builder import DependencyGraphBuilder
from test_strategy_engine import TestStrategyEngine
from runtime_executor import RequestExecutor
from llm_planner import LLMPlanner
from state_store import StateStore
from rule_inference_layer import RuleInferenceLayer
from knowledge_memory import KnowledgeMemory
from generate_report import generate_html_report

import argparse

def build_system(operations, base_url, beam_width):
    # DI Containers
    planner = LLMPlanner()
    rule_layer = RuleInferenceLayer(planner, operations)
    knowledge_memory = KnowledgeMemory()
    
    # Graph Builder
    graph_builder = DependencyGraphBuilder(
        operations=operations, 
        rule_layer=rule_layer, 
        planner=planner
    )
    adjacency_list = graph_builder.build_scientific_odg(output_file="ODG_Scientific_Final.dot")

    # Request Executor
    request_executor = RequestExecutor(
        base_url=base_url,
        planner=planner,
        knowledge_memory=knowledge_memory
    )

    # Strategy Engine
    strategy_engine = TestStrategyEngine(
        operations=operations,
        adjacency_list=adjacency_list,
        request_executor=request_executor,
        graph_builder=graph_builder,
        knowledge_memory=knowledge_memory,
        beam_width=beam_width
    )

    return strategy_engine, knowledge_memory

def main():
    parser = argparse.ArgumentParser(description="Hybrid Stateful API Fuzzer")
    parser.add_argument("--spec", type=str, default="vmAPI.json", help="Path to OpenAPI spec file")
    parser.add_argument("--base-url", type=str, default="http://localhost:5001", help="Target API Base URL")
    parser.add_argument("--max-depth", type=int, default=5, help="Max depth for path execution")
    parser.add_argument("--beam-width", type=int, default=3, help="Beam search width")
    args = parser.parse_args()

    print("=== Hệ thống Phân tích và Xây dựng Chiến lược Kiểm thử API (Component-Based DI) ===")

    # ── Phase 1: Phân tích OpenAPI Spec ──────────────────────────────────────
    print(f"\n[Phase 1] Đang phân tích OpenAPI Specification từ {args.spec}...")
    parser_obj = SpecParser(args.spec)
    operations = parser_obj.extract_operations()
    if not operations:
        print("[-] Không tìm thấy operations nào hoặc lỗi khi đọc spec.")
        return
    print(f"[*] Đã trích xuất {len(operations)} operations từ spec.")

    # ── Phase 2: Khởi tạo Hệ Thống qua Dependency Injection ──────────────────
    print("\n[Phase 2] Khởi tạo các module hệ thống (DI)...")
    strategy_engine, knowledge_memory = build_system(operations, args.base_url, args.beam_width)

    # ── Phase 0: Cấu hình State Store từ biến môi trường ─────────────────────
    print(f"\n[Phase 0] Khởi tạo StateStore với cấu hình người dùng...")
    auth_token = os.getenv("AUTH_TOKEN", "")
    auth_header_name = os.getenv("AUTH_HEADER_NAME", "Authorization")
    auth_header_prefix = os.getenv("AUTH_HEADER_PREFIX", "")
    
    initial_state_data = {}
    
    # Luôn nạp cấu hình Header từ .env
    initial_state_data["auth_header_name"] = auth_header_name
    initial_state_data["auth_header_prefix"] = auth_header_prefix

    if auth_token:
        initial_state_data["auth_token"] = auth_token
        print("[Phase 0] ✓ Đã nạp auth_token và cấu hình Header từ biến môi trường .env")
    else:
        print("[Phase 0] ⚠ Không tìm thấy AUTH_TOKEN trong .env — Fuzzer chạy unauthenticated (hoặc tự login).")

    # Đọc các biến mồi (Seed) từ .env có tiền tố SEED_
    seed_count = 0
    for key, value in os.environ.items():
        if key.startswith("SEED_"):
            # Lấy tên biến sau chữ SEED_ (ví dụ SEED_email -> email)
            state_key = key[5:]
            initial_state_data[state_key] = value
            seed_count += 1
            
    if seed_count > 0:
        print(f"[Phase 0] ✓ Đã nạp {seed_count} biến mồi (Seed) bổ sung vào StateStore.")
        
    initial_state = StateStore(initial_state_data)

    # ── Phase 3: Khởi chạy Fuzzer (Live HTTP) ────────────────────────────────
    print(f"\n[Phase 3] Khởi chạy Test Strategy Engine → {args.base_url}")
    best_chains = strategy_engine.run(max_depth=args.max_depth, initial_state=initial_state)

    # ── Xuất kết quả ─────────────────────────────────────────────────────────
    # Lưu vào format tương thích với generate_html_report
    knowledge_memory.set_top_strategies(best_chains)
    knowledge_memory.export("beam_strategies.json")
    
    # ── Tạo báo cáo HTML Dashboard ───────────────────────────────────────────
    print("\n[*] Đang tạo báo cáo HTML Dashboard...")
    generate_html_report("beam_strategies.json", "fuzzing_report")
    
    print("\n=== Hoàn thành toàn bộ hệ thống! ===")

if __name__ == "__main__":
    main()