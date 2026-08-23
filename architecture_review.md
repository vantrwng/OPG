# Báo cáo Đánh giá Kiến trúc Hệ thống (Architectural Review)
**Dự án**: Hybrid Stateful API Fuzzer (OPG)
**Ngày đánh giá**: 20/06/2026

Dựa trên tiêu chuẩn `cc-skill-architect-review`, dưới đây là đánh giá chi tiết về cấu trúc kiến trúc hiện tại của dự án API Fuzzer.

---

## 1. Phân tích Hiện trạng (System Context)
Hệ thống là một công cụ kiểm thử bảo mật API (Fuzzer) hoạt động theo cơ chế **Hybrid Stateful**. Kiến trúc hệ thống bao gồm 3 giai đoạn chính:
- **Static Analysis (Offline)**: Phân tích OpenAPI Spec (`spec_parser.py`) và xây dựng Đồ thị Phụ thuộc (`graph_builder.py`).
- **Fuzzing Engine**: Điều phối các chiến lược kiểm thử bằng thuật toán BFS / Beam Search / MCTS (`test_strategy_engine.py`).
- **Runtime Execution**: Thực thi request thực tế, quản lý trạng thái (`state_store.py`) và ghi nhận dữ liệu (`knowledge_memory.py`).

---

## 2. Điểm sáng trong Kiến trúc (Architectural Strengths)

### 2.1. Triển khai Dependency Injection (DI)
File `main.py` (hàm `build_system`) đã áp dụng tốt pattern **Dependency Injection** (Constructor Injection). Thay vì các class tự khởi tạo lẫn nhau (tight coupling), `main.py` đóng vai trò là DI Container, khởi tạo `LLMPlanner`, `RuleInferenceLayer`, `KnowledgeMemory`, `GraphBuilder` và bơm (inject) chúng vào `TestStrategyEngine`. 
* **Lợi ích**: Tăng tính Testability, dễ dàng mock các thành phần khi viết Unit Test.

### 2.2. Trạng thái Độc lập (State Isolation)
Việc sử dụng pattern `StateStore.clone()` khi Beam Search rẽ nhánh là một quyết định thiết kế xuất sắc. Trong các hệ thống phân tán hoặc fuzzer đa luồng, việc chia sẻ memory chung dễ dẫn đến Race Condition. Pattern này tuân thủ nguyên tắc **Immutability** ở cấp độ luồng dữ liệu.

### 2.3. Tách biệt Báo cáo (Decoupled Reporting)
Kiến trúc đã tách rời hoàn toàn quá trình sinh báo cáo (`generate_report.py`) khỏi quá trình Fuzzing. Giao tiếp giữa 2 module này được thực hiện qua một contract chuẩn (file `beam_strategies.json`). Đây là ứng dụng tốt của nguyên lý **Separation of Concerns (SoC)**.

---

## 3. Các Rủi ro & Vi phạm Kiến trúc (Anti-patterns & Risks)

### 3.1. Tài liệu lỗi thời (Documentation Drift)
* **Vấn đề**: Tệp `SYSTEM_ARCHITECTURE.md` đang mô tả module Fuzzer là `hybrid_fuzzer.py` với class `HybridBeamFuzzer`. Tuy nhiên, mã nguồn thực tế lại sử dụng `test_strategy_engine.py` và `TestStrategyEngine`.
* **Rủi ro**: Vi phạm nguyên tắc **Architecture Documentation Governance**. Tài liệu không đồng bộ sẽ gây khó khăn lớn cho việc onboarding thành viên mới hoặc khi bảo trì sau này.

### 3.2. Cấu trúc Khởi động "Spaghetti" (Startup Sequence Anomaly)
* **Vấn đề**: Trong `main.py`, luồng thực thi bị nhảy cóc: `[Phase 1] -> [Phase 2] -> [Phase 0] -> [Phase 3]`. Việc cấu hình môi trường (`Phase 0`) lại diễn ra *sau khi* khởi tạo hệ thống (DI Container).
* **Rủi ro**: Không tuân thủ nguyên tắc **Fail-Fast**. Nếu cấu hình môi trường bị lỗi, hệ thống vẫn mất thời gian khởi tạo các objects nặng (LLM, Graph) rồi mới crash.

### 3.3. Dấu hiệu của "God Object" (Over-injection)
* **Vấn đề**: `TestStrategyEngine` đang nhận vào quá nhiều dependencies: `operations`, `adjacency_list`, `request_executor`, `graph_builder`, `knowledge_memory`. 
* **Rủi ro**: Vi phạm nguyên lý **Single Responsibility Principle (SRP)**. Engine này đang phải biết quá nhiều về hệ thống (từ việc tạo graph đến việc gọi API và lưu knowledge). 

### 3.4. Vấn đề Hiệu năng (Scalability & Concurrency Bottleneck)
* **Vấn đề**: Với các thuật toán nặng như MCTS (Monte Carlo Tree Search) và Beam Search, kết hợp với gọi I/O mạng liên tục, Python GIL (Global Interpreter Lock) sẽ trở thành điểm nghẽn cổ chai lớn nhất nếu hệ thống chạy đồng bộ (Synchronous).
* **Rủi ro**: Hệ thống không thể Scale theo chiều ngang (Horizontal Scaling) nếu muốn fuzz hàng chục nghìn endpoint cùng lúc.

---

## 4. Đề xuất Tái cấu trúc (Recommendations)

### Giai đoạn 1: Refactoring ngay lập tức (Low Effort, High Impact)
1. **Sửa lại Startup Sequence trong `main.py`**:
   Chuyển toàn bộ logic đọc `.env` (Phase 0) lên đầu tiên. Đóng gói logic này vào một class `AppConfig` (Singleton hoặc Data Class) theo pattern **Options Pattern**.
2. **Cập nhật SYSTEM_ARCHITECTURE.md**: 
   Sửa đổi tài liệu kiến trúc để phản ánh đúng tên class `TestStrategyEngine` hiện tại.

### Giai đoạn 2: Refactoring cấu trúc (Medium Effort)
1. **Áp dụng Observer / Event-Driven Pattern**:
   Thay vì truyền `KnowledgeMemory` và `GraphBuilder` vào tận bên trong `TestStrategyEngine`, hãy thiết kế Engine này phát ra các sự kiện (ví dụ: `on_request_success`, `on_anomaly_detected`). Các module khác sẽ "lắng nghe" (subscribe) các sự kiện này để cập nhật đồ thị và bộ nhớ. Điều này giúp giải phóng "God Object".

### Giai đoạn 3: Tối ưu hiệu năng (High Effort)
1. **Chuyển đổi I/O sang Asynchronous**:
   Refactor `RequestExecutor` sử dụng `asyncio` và `aiohttp`. Kiến trúc Fuzzer hiện đại bắt buộc phải là Non-blocking I/O để tối đa hóa số lượng request / giây (RPS).
2. **Chuẩn bị cho Phân tán (Distributed Fuzzing)**:
   Nếu dự án phát triển, hãy cân nhắc tách `TestStrategyEngine` (Bộ não - Master) và `RequestExecutor` (Chân tay - Worker). Worker có thể chạy trên nhiều container khác nhau và giao tiếp qua Message Queue (Redis / RabbitMQ).

---

## Tổng kết (Executive Summary)
Kiến trúc hiện tại của dự án OPG đang có nền tảng rất vững chắc với việc áp dụng DI và State Isolation. Tuy nhiên, hệ thống đang bắt đầu xuất hiện các "technical debt" về sự gắn kết (coupling) bên trong hàm lõi và sự lệch pha giữa tài liệu và mã nguồn. Cần sớm áp dụng Event-Driven Pattern để giảm tải cho `TestStrategyEngine` trước khi mở rộng thêm tính năng mới.
