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

from spec_parser import SpecParser
from graph_builder import DependencyGraphBuilder
from test_strategy_engine import TestStrategyEngine
from runtime_executor import BootstrapExecutor, RequestExecutor
from llm_planner import LLMPlanner
from rule_inference_layer import RuleInferenceLayer
from knowledge_memory import KnowledgeMemory
from generate_report import generate_html_report

TARGET_URL = "http://localhost:8888"  # ← Đổi sang URL của server mục tiêu

def build_system(operations):
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
        base_url=TARGET_URL,
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
        beam_width=5
    )

    return strategy_engine, knowledge_memory

def main():
    print("=== Hệ thống Phân tích và Xây dựng Chiến lược Kiểm thử API (Component-Based DI) ===")

    # ── Phase 1: Phân tích OpenAPI Spec ──────────────────────────────────────
    print("\n[Phase 1] Đang phân tích OpenAPI Specification...")
    spec_file = 'crapi-openapi-spec.json'
    parser    = SpecParser(spec_file)
    operations = parser.extract_operations()
    if not operations:
        print("[-] Không tìm thấy operations nào hoặc lỗi khi đọc spec.")
        return
    print(f"[*] Đã trích xuất {len(operations)} operations từ spec.")

    # ── Phase 2: Khởi tạo Hệ Thống qua Dependency Injection ──────────────────
    print("\n[Phase 2] Khởi tạo các module hệ thống (DI)...")
    strategy_engine, knowledge_memory = build_system(operations)

    # ── Phase 0 (Bootstrap): Signup → Login → Lấy auth_token ─────────────────
    print(f"\n[Phase 0] Bootstrap: Signup → Login trên {TARGET_URL}...")
    bootstrapper   = BootstrapExecutor(base_url=TARGET_URL)
    initial_state  = bootstrapper.bootstrap()

    if initial_state.has("auth_token"):
        print("[Phase 0] ✓ auth_token đã sẵn sàng — bắt đầu Fuzzing với session đã xác thực.")
    else:
        print("[Phase 0] ⚠ Không lấy được token — Fuzzer sẽ chạy ở chế độ unauthenticated.")

    # ── Phase 3: Khởi chạy Fuzzer (Live HTTP) ────────────────────────────────
    print(f"\n[Phase 3] Khởi chạy Test Strategy Engine → {TARGET_URL}")
    best_chains = strategy_engine.run(max_depth=10, initial_state=initial_state)

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