# Thuật toán Scalable Semantic OPG (V3)

Module `graph_builder.py` là trái tim của bộ máy Phân tích tĩnh (Static Analysis). Nhiệm vụ của nó là xây dựng một Đồ thị Phụ thuộc (Operation Dependency Graph - ODG) kết nối các API lại với nhau mà không cần chạy code thực tế.

Thiết kế hiện tại (Version 3) là một kiến trúc Đẳng cấp Nghiên cứu (Research-grade), vượt xa các thuật toán "So sánh từ khóa" (Lexical Matching) truyền thống bằng 5 cơ chế cốt lõi sau:

---

## 1. Cơ chế Lập chỉ mục Ngữ nghĩa (Inverted Semantic Index)
**Vấn đề:** Nếu file API có $N$ endpoints, mỗi endpoint có $F$ fields. Việc so sánh chéo tất cả tạo ra độ phức tạp $O(N^2 \times F^2)$. Chạy trên một hệ thống lớn (1000 APIs) sẽ mất hàng giờ.

**Giải pháp (V3):**
Thuật toán chia toàn bộ các tham số của hệ thống vào các rổ (Buckets) ngữ nghĩa riêng biệt.
- **Identity Bucket:** `[user_id, patientNo, email, ref...]`
- **Auth/Workflow Bucket:** `[token, session, status...]`
- **Finance Bucket:** `[balance, payment_amount...]`

Khi nối đồ thị, hệ thống **CHỈ so sánh các tham số nằm chung trong 1 rổ**. Việc này giúp độ phức tạp giảm thẳng đứng xuống còn $O(K \log K)$, giải quyết toàn bộ bài toán Scalability (Khả năng mở rộng).

---

## 2. Tokenized Matching & Semantic Aliasing
Thuật toán phân mảnh chuỗi (Tokenize) để tránh các lỗi nhận diện ngớ ngẩn do Substring Matching gây ra (Ví dụ: Chữ `video` chứa cụm `id` $\rightarrow$ Nhầm thành trường ID).
Bên cạnh đó, hệ thống sử dụng **Semantic Aliases**:
Tất cả các từ đồng nghĩa nghiệp vụ như `customer`, `member`, `subscriber`, `account` đều được thuật toán tự động quy hoạch chung về nhóm `Identity`. Đây là nền tảng của một Semantic Graph thực thụ.

---

## 3. Trừng phạt Từ dừng (Stopword Penalty)
**Vấn đề:** Các API thường có trường `{"status": "success"}`. Nếu thuật toán so sánh mù quáng, nó sẽ nối trường `status` này với trường `payment_status` (Trạng thái thanh toán) của API khác, tạo ra muôn vàn cạnh giả (Fake Edges / Spaghetti Graph).

**Giải pháp:** 
Thuật toán đánh giá Context (Ngữ cảnh). Nếu một trường chỉ chứa độc nhất một từ Generic (Stopword) như `status`, `number`, `state` $\rightarrow$ Điểm tin cậy (Confidence Score) của nó bị áp dụng lệnh trừng phạt (Penalty) giảm đi $60\%$. 
Nhờ đó, cạnh giả `status -> payment_status` bị đứt gãy, trong khi cạnh xương sống `payment_status -> payment_status` vẫn trụ vững với điểm tuyệt đối.

---

## 4. API Role Awareness (Định hướng Phương thức)
Một cạnh được đánh giá không chỉ dựa trên Tên biến, mà còn dựa trên Hành vi của Phương thức (Directionality):
- `GET`: Consumer (Đọc dữ liệu)
- `POST/PUT/PATCH`: Producer/Mutator (Tạo/Sửa dữ liệu)
- Nếu thuật toán phát hiện một luồng dữ liệu chảy ngược từ `GET` $\rightarrow$ `POST` (Lấy dữ liệu từ hàm Đọc để điền vào hàm Tạo mới), nó tự động áp dụng hệ số phạt $0.6$ cho cạnh đó, bởi vì đây là một hướng đi bất thường (Unnatural Flow).

---

## 5. Lưu trữ Đa phụ thuộc (Merged Edge Metadata)
Thay vì chỉ giữ lại 1 sự liên kết mạnh nhất giữa 2 API, hệ thống bảo tồn **Top 2 Phụ thuộc (Dependencies)** trên cùng một cạnh.
- *Ví dụ:* API `GetUserInfo` cung cấp cho API `UpdatePassword` cả 2 trường: `email` (Identity) và `token` (Auth).
- Đồ thị sẽ hiển thị cả 2 sự phụ thuộc này trên 1 mũi tên duy nhất. Điều này cung cấp đủ thông tin (State Context) để Fuzzer biết rằng nó phải thoả mãn đồng thời cả 2 điều kiện mới có thể Bypass được API đích.

---

### Tổng kết Kết quả
Thuật toán V3 tạo ra một đồ thị **Sparse Weighted ODG** (Đồ thị thưa có trọng số). Số lượng cạnh được kiểm soát chặt chẽ (Nhờ Stopword Penalty), độ chính xác ngữ nghĩa cực cao (Nhờ Tokenized & Aliasing), và tốc độ thực thi trong vài giây (Nhờ Inverted Index). Đây là công cụ chuẩn bị dữ liệu hoàn hảo cho Stateful Fuzzer.
