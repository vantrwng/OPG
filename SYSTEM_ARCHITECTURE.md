# Kiến trúc Hệ thống: Hybrid Stateful API Fuzzer

## Sơ đồ Tổng thể (System Architecture)

![System Architecture Diagram](C:\Users\LONGTRIEU\.gemini\antigravity\brain\d81c9840-98e6-48dc-97e7-264be88df867\system_architecture_diagram_1778486734337.png)

---

## Sơ đồ Luồng Dữ liệu (Data Flow — Mermaid)

```mermaid
graph TD
    %% ============ PHASE 1: STATIC ANALYSIS ============
    subgraph P1 ["⚙️  Phase 1 · Static Analysis (Offline)"]
        SPEC["📄 crapi-openapi-spec.json"]
        SP["spec_parser.py\n──────────────────\nSpecParser\n• normalize_word()\n• apply_id_completion()\n• extract_operations()"]
        GB["graph_builder.py\n──────────────────\nDependencyGraphBuilder\n• is_noisy() — Contextual Blacklist\n• classify_semantic() — Aliasing\n• Inverted Semantic Index  O(K log K)\n• Stopword Penalty\n• get_directionality_score()\n• build_scientific_odg()"]
        DOT["📊 ODG_Scientific_Final.dot\n(Sparse Weighted Graph)"]
    end

    %% ============ PHASE 2: FUZZING ENGINE ============
    subgraph P2 ["🔍  Phase 2 · Fuzzing Engine"]
        HBF["test_strategy_engine.py\n──────────────────\nTestStrategyEngine\n• run(max_depth=10)\n• run_security_phase()"]

        CBM["CoverageBucketManager\n• buckets: auth / admin / crud / other\n• Top-K per bucket\n• Jaccard Diversity Penalty"]

        HS["HeuristicScorer\n• 500 → +100 pts\n• auth_anomaly → +80 pts\n• state_transition → +40 pts\n• Visit-count exploration heuristic"]
    end

    %% ============ PHASE 3: RUNTIME EXECUTION ============
    subgraph P3 ["🚀  Phase 3 · Runtime Execution"]
        RE["runtime_executor.py\n──────────────────\nRequestExecutor\n• execute_request(api_id, state)"]
        SS["StateStore\n• Lưu token, ID, entity_id\n• .clone() — Rẽ nhánh Beam độc lập"]
        FA["FeedbackAnalyzer\n• extract_new_state()\n• analyze_anomalies()\n• Phát hiện BOLA / BFLA"]
    end

    OUT["📁 beam_strategies.json\n(Top strategies output)"]

    %% ============ EDGES ============
    SPEC -->|"parse & normalize"| SP
    SP -->|"operations[]"| GB
    GB -->|"adjacency_list"| HBF
    GB -->|"render"| DOT

    HBF -->|"Beam Search từ depth 1"| CBM
    CBM -->|"score chain"| HS
    HS -->|"ranked chains"| HBF

    HBF -->|"execute_request()"| RE
    RE -->|"update"| SS
    RE -->|"analyze"| FA
    FA -.->|"Runtime Edge Reinforcement\nupdate_edge_confidence()"| GB
    SS -.->|"StateStore.clone()\nper beam branch"| HBF

    HBF -->|"export_results()"| OUT
```

---

## Mô tả từng Module

| File | Class chính | Vai trò |
|------|-------------|---------|
| `spec_parser.py` | `SpecParser` | Đọc OpenAPI JSON, chuẩn hóa tên field (Id Completion, Stemming), trả về `operations[]` |
| `graph_builder.py` | `DependencyGraphBuilder` | Xây dựng Sparse Weighted ODG bằng Inverted Semantic Index, Stopword Penalty, Directionality Scoring |
| `test_strategy_engine.py` | `TestStrategyEngine` | Điều phối Beam Search, coverage bucket và pha kiểm thử bảo mật |
| `runtime_executor.py` | `RequestExecutor` | Gửi HTTP thật, rẽ nhánh StateStore, phân tích response |

## Các cơ chế cốt lõi

### 1. Inverted Semantic Index (O(K log K))
Thay vì duyệt O(N² × F²), `DependencyGraphBuilder` **băm field vào semantic bucket** (`identity`, `auth/workflow`, `finance`) trước. Chỉ các field trong cùng bucket mới được so sánh chéo.

### 2. Beam Search từ độ sâu đầu tiên
`TestStrategyEngine.calculate_adaptive_bfs_threshold()` hiện trả về cố định `0`. Vì vậy coverage bucket và giới hạn beam được áp dụng ngay từ depth 1 để khống chế bùng nổ tổ hợp.

### 3. Visit-count Exploration Heuristic
Mỗi node được gắn `visit_count`. Score của node = `base_score + 50 / √visit_count`. Đây là heuristic ưu tiên node ít được thăm, không phải triển khai đầy đủ MCTS/UCT.

### 4. Stateful Beam Branching
Khi Beam rẽ nhánh sang API tiếp theo, `StateStore.clone()` tạo ra **bản sao bộ nhớ độc lập** cho nhánh đó. Các token/ID không bị lẫn lộn giữa các chuỗi tấn công song song.

### 5. Runtime Edge Reinforcement
`DependencyGraphBuilder.update_edge_confidence(api_out, api_in, success)` tự động **điều chỉnh trọng số cạnh** trong đồ thị dựa trên kết quả thực thi:
- Thành công → `confidence × 1.1`
- Thất bại → `confidence × 0.8`

---

## Đầu ra (Outputs)

| File | Nội dung |
|------|----------|
| `ODG_Scientific_Final.dot` | Đồ thị phụ thuộc dạng Graphviz (có màu theo semantic type) |
| `beam_strategies.json` | Các chuỗi API tấn công tốt nhất, kèm score & final_state |
