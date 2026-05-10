import random
import copy
import re

class StateStore:
    """Kho lưu trữ Context/Memory cho từng chùm tia (Beam) trong suốt quá trình Fuzzing"""
    def __init__(self, initial_state=None):
        self.memory = initial_state if initial_state else {}

    def update(self, key, value):
        self.memory[key] = value

    def get(self, key, default=None):
        return self.memory.get(key, default)

    def has(self, key):
        return key in self.memory

    def clone(self):
        """Nhân bản StateStore để rẽ nhánh đồ thị (Beam split) mà không bị đè dữ liệu"""
        return StateStore(copy.deepcopy(self.memory))
        
    def __str__(self):
        return str(self.memory)

class FeedbackAnalyzer:
    """Máy phân tích Phản hồi thực tế từ Server để trích xuất State mới và đánh giá Anomaly"""
    def __init__(self):
        pass

    def extract_new_state(self, api_id, mock_response, state_store):
        """
        Trích xuất các ID/Token động từ Response JSON.
        Vì đang chạy ở chế độ Mock, chúng ta sẽ giả lập việc phát hiện ID dựa trên tên API.
        Trong thực tế, hàm này sẽ parse JSON: e.g. json_data.get('id')
        """
        api_id_lower = api_id.lower()
        new_state_found = False
        
        # Giả lập: Các API create/login sinh ra data mới
        if mock_response['status'] in [200, 201]:
            if 'login' in api_id_lower or 'token' in api_id_lower:
                state_store.update("auth_token", f"mock_token_{random.randint(1000, 9999)}")
                new_state_found = True
            elif 'create' in api_id_lower or 'post' in api_id_lower:
                # Tìm danh từ đằng sau chữ create (e.g. create_vehicle -> vehicle)
                match = re.search(r'(?:create|post)_([a-z]+)', api_id_lower)
                if match:
                    entity = match.group(1)
                    state_store.update(f"{entity}_id", random.randint(1, 100))
                    new_state_found = True
                else:
                    state_store.update(f"generic_id", random.randint(1, 100))
                    new_state_found = True
                    
        return new_state_found

    def analyze_anomalies(self, api_id, mock_response, state_store):
        """Phân tích các bất thường về phân quyền hoặc thay đổi payload đột ngột"""
        api_id_lower = api_id.lower()
        status = mock_response['status']
        
        auth_anomaly = False
        response_diff = False
        
        if status == 200:
            # Nếu gọi API admin mà trong State chưa hề có Token admin -> Auth Bypass (BOLA/BFLA)
            if 'admin' in api_id_lower and not state_store.has('admin_token'):
                auth_anomaly = random.random() < 0.2 # 20% khả năng dính lỗi thực sự
                
            # Random Excessive Data exposure
            if random.random() < 0.1:
                response_diff = True
                
        return auth_anomaly, response_diff

class RequestExecutor:
    """Cỗ máy thực thi Request thật lên Server (hiện tại đang Mock)"""
    def __init__(self):
        self.analyzer = FeedbackAnalyzer()

    def execute_request(self, api_id, state_store):
        """
        Thực thi API.
        Trong thực tế: Gọi LLM sinh payload dựa trên OpenAPI Spec + biến từ state_store, sau đó dùng thư viện `requests`.
        Hiện tại: Trả về Mock Response.
        """
        status_options = [200, 201, 400, 401, 403, 404, 500, 202, 422]
        # Nếu StateStore có auth_token, tỷ lệ thành công (200) sẽ cao hơn
        if state_store.has('auth_token'):
            weights = [70, 10, 5, 2, 2, 5, 2, 2, 2] 
        else:
            weights = [30, 10, 10, 20, 20, 5, 2, 2, 1]
            
        status = random.choices(status_options, weights=weights)[0]
        
        mock_raw_response = {
            'status': status,
            'body': '{"mock": "data"}'
        }
        
        # Đưa cho FeedbackAnalyzer phân tích
        state_transition = self.analyzer.extract_new_state(api_id, mock_raw_response, state_store)
        auth_anomaly, response_diff = self.analyzer.analyze_anomalies(api_id, mock_raw_response, state_store)
        
        return {
            'status': status,
            'auth_anomaly': auth_anomaly,
            'state_transition': state_transition,
            'response_diff': response_diff
        }
