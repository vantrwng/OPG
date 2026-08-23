import json
import time
from collections import deque

class KnowledgeMemory:
    """
    Lưu trữ kiến thức trong thời gian chạy (Runtime state), 
    thu thập thống kê chi tiết, và xuất báo cáo.
    """
    # Giới hạn tối đa để tránh OOM khi chạy lâu trên API lớn
    _MAX_HISTORY       = 10_000  # Tổng request history giữ lại
    _MAX_PER_ENDPOINT  = 200     # Tối đa request/endpoint trong endpoint_stats

    def __init__(self):
        self.found_vulnerabilities = set() # Set cho fast lookup f"{api_id}:{status}"
        self.node_visit_count = {}
        self.top_strategies = []
        
        # Thống kê mở rộng
        self.request_history: deque = deque(maxlen=self._MAX_HISTORY)  # bounded
        self.findings = []
        self.endpoint_stats = {}
        self.edge_feedback = {}

    def record_visit(self, api_id: str):
        if api_id not in self.node_visit_count:
            self.node_visit_count[api_id] = 0
            self.endpoint_stats[api_id] = {"visits": 0, "status_counts": {}}
        self.node_visit_count[api_id] += 1
        self.endpoint_stats[api_id]["visits"] += 1

    def get_visit_count(self, api_id: str) -> int:
        return self.node_visit_count.get(api_id, 0)

    def record_request(self, api_id: str, method: str, path: str, status: int, chain: list = None, response_text: str = None, request_payload: dict = None, payload_source: str = "NONE", repair_reason: str = "", repair_history: list = None, sent_headers: dict = None):
        if api_id not in self.endpoint_stats:
            self.endpoint_stats[api_id] = {"visits": 0, "status_counts": {}, "all_requests": []}
        
        stats = self.endpoint_stats[api_id]["status_counts"]
        all_requests = self.endpoint_stats[api_id].setdefault("all_requests", [])
        status_str = str(status)
        stats[status_str] = stats.get(status_str, 0) + 1
        
        # Giới hạn số lượng request lưu trữ per-endpoint để tránh OOM
        if len(all_requests) >= self._MAX_PER_ENDPOINT:
            all_requests.pop(0)  # Xóa record cũ nhất
        
        all_requests.append({
            "method": method,
            "path": path,
            "status": status_str,
            "request_payload": request_payload if request_payload is not None else {},
            "response_text": response_text if response_text is not None else "",
            "payload_source": payload_source,
            "repair_reason": repair_reason,
            "repair_history": repair_history if repair_history is not None else [],
            "sent_headers": sent_headers if sent_headers is not None else {},
            "chain": chain if chain is not None else []
        })
        
        self.request_history.append({
            "api_id": api_id,
            "method": method,
            "path": path,
            "status": status,
            "chain_length": len(chain) if chain else 0,
            "timestamp": time.time()
        })

    def record_finding(self, finding: dict):
        self.findings.append(finding)
        
    def record_edge_feedback(self, from_api: str, to_api: str, success: bool):
        key = f"{from_api}->{to_api}"
        if key not in self.edge_feedback:
            self.edge_feedback[key] = {"success": 0, "failure": 0}
        if success:
            self.edge_feedback[key]["success"] += 1
        else:
            self.edge_feedback[key]["failure"] += 1
        
    def record_vulnerability(self, api_id: str, status: int):
        self.found_vulnerabilities.add(f"{api_id}:{status}")

    def is_vulnerability_found(self, api_id: str, status: int) -> bool:
        return f"{api_id}:{status}" in self.found_vulnerabilities

    def add_strategy(self, strategy: dict):
        self.top_strategies.append(strategy)

    def set_top_strategies(self, strategies: list):
        self.top_strategies = strategies

    def export(self, output_file: str):
        # Tổng hợp thống kê
        total_requests = len(self.request_history)
        server_errors = sum(1 for f in self.findings if f.get("type") == "Crash/500")
        auth_anomalies = sum(1 for f in self.findings if f.get("type") == "Auth Anomaly")
        
        output_data = {
            "summary": {
                "total_requests": total_requests,
                "server_errors_500": server_errors,
                "auth_anomalies": auth_anomalies,
                "total_strategies_found": len(self.top_strategies),
                "total_findings": len(self.findings)
            },
            "endpoint_stats": self.endpoint_stats,
            "edge_feedback": self.edge_feedback,
            "findings": self.findings,
            "top_strategies": self.top_strategies
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        print(f"[*] Đã xuất {len(self.top_strategies)} chiến thuật tối ưu và {len(self.findings)} findings ra file {output_file}")
