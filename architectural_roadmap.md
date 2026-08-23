# Roadmap & Thiết kế Kiến trúc: Hybrid Stateful API Fuzzer

**Dự án**: OPG API Fuzzer
**Định hướng**: Phát triển qua 2 giai đoạn học thuật (Đồ án Chuyên ngành & Đồ án Tốt nghiệp).

---

## 1. Tóm tắt sự hiểu biết (Understanding Summary)
* **Sản phẩm**: Một kiến trúc mở rộng cho hệ thống API Fuzzer.
* **Mục đích**: Tối ưu hóa hệ thống để đáp ứng đúng yêu cầu của từng giai đoạn học thuật.
* **Đối tượng**: API RESTful nội bộ hoặc Public có khả năng chịu tải cao.
* **Ràng buộc chính**:
  * **Giai đoạn 1**: Chỉ tập trung tạo lỗi **HTTP 500** (Crash) mà không dùng thêm Agent AI nào để tối ưu chi phí và bám sát triết lý RESTler.
  * **Giai đoạn 2**: Nâng cấp lên hệ thống **Security Scanner** phát hiện lỗi mức Logic (như BOLA/IDOR), bắt buộc phải tích hợp kiến trúc **Multi-Agent** chạy Local.
* **Non-goals**: Không vứt bỏ hoặc viết lại thuật toán lõi (MCTS, ODG, Beam Search); chúng vẫn sẽ là hệ thống "Dẫn đường".

## 2. Các Giả định (Assumptions)
* API mục tiêu chịu tải tốt, cho phép Fuzzer bắn hàng trăm request trong thời gian ngắn.
* Hạ tầng thiết bị (của sinh viên) có đủ khả năng để cấu hình Ollama chạy các mô hình nhỏ gọn (7B-8B parameters) cho Giai đoạn 2.

## 3. Nhật ký quyết định (Decision Log)
1. **Quyết định**: Sử dụng kiến trúc `Sequence-then-Blast` (Đi đường chuẩn rồi xả đạn) cho Giai đoạn 1.
   * *Lý do*: Đáp ứng chính xác nhu cầu gây lỗi 500 (Robustness) mà không phát sinh thêm chi phí GPT API.
2. **Quyết định**: Sử dụng `aiohttp` để viết module đột biến dữ liệu `LocalMutator`.
   * *Lý do*: Đảm bảo khả năng gửi request bất đồng bộ (Asynchronous) để ép server vào tình trạng tải cao/phá vỡ logic parse.
3. **Quyết định**: Thiết lập kiến trúc Multi-Agent (Architect, Attacker, Auditor) chạy qua Ollama cho Giai đoạn 2.
   * *Lý do*: Thay đổi tính chất Fuzzing từ việc tìm lỗi Crash (500) sang tìm lỗi bảo mật trên response hợp lệ (200), phù hợp với đề tài Đồ án Tốt nghiệp xuất sắc.

---

## 4. Thiết kế Kiến trúc Cuối cùng (Final Design)

### Giai đoạn 1 (Đồ án Chuyên ngành): Robustness Fuzzer
* **Mục tiêu**: Fuzz tìm Unhandled Exception (HTTP 500).
* **Component mới**: `local_mutator.py`
  * Chứa bộ `FuzzDictionary` (SQLi, Null byte, Buffer Overflow strings, Integer Boundaries).
  * Chứa `AsyncFuzzEngine` để bắn request đa luồng.
* **Workflow**: 
  1. `TestStrategyEngine` sử dụng Heuristic/LLM để lấy được Payload chuẩn (HTTP 200).
  2. Bàn giao Payload chuẩn này cho `AsyncFuzzEngine`.
  3. `AsyncFuzzEngine` biến đổi Payload chuẩn theo bộ `FuzzDictionary` và bắn 100 requests bất đồng bộ vào Endpoint.
  4. Ghi nhận lỗi 500 vào Report.

### Giai đoạn 2 (Đồ án Tốt nghiệp): Security Multi-Agent Scanner
* **Mục tiêu**: Fuzz tìm lỗ hổng Logic/Phân quyền (BOLA, IDOR, Auth Bypass).
* **Kiến trúc AI**: Multi-Agent System (Ollama Local Models).
* **Thành phần Agents**:
  1. **Architect Agent (Llama 3.1 8B)**: Phân tích ODG, chỉ định các endpoint có nguy cơ bảo mật cao.
  2. **Attacker Agent (Qwen2.5 Coder 7B)**: Biến đổi Payload chuẩn mang tính chất lừa đảo (Đổi ID, xóa Token, nâng quyền).
  3. **Auditor Agent (Llama 3.1 8B)**: Phân tích JSON trả về (dù mã 200 OK) để kết luận có bị lộ thông tin nhạy cảm hay không.
* **Workflow**:
  1. Khi Thuật toán chỉ đường đưa fuzzer tới endpoint nhạy cảm.
  2. Kích hoạt nhóm Đặc nhiệm AI. Chúng phối hợp tạo payload giả mạo và phân tích response để đánh giá mức độ vi phạm bảo mật.
