import json
import re
import random
import math
from runtime_executor import StateStore, RequestExecutor

# Giới hạn an toàn: số lượng beams tối đa trong giai đoạn BFS
# Ngăn bùng nổ bộ nhớ O(BF^depth) trên đồ thị dày đặc
MAX_BFS_BEAMS = 500

def jaccard_similarity(list1, list2):
    """Tính độ tương đồng Jaccard giữa 2 tập hợp"""
    s1 = set(list1)
    s2 = set(list2)
    union_len = len(s1.union(s2))
    if union_len == 0:
        return 0
    return len(s1.intersection(s2)) / union_len

class HeuristicScorer:
    def __init__(self):
        # Các status code được coi là thông thường (spam 200, 201, 204)
        self.common_statuses = {200, 201, 204, 401, 403, 404}

    def calculate_score(self, response_mock, depth, visit_count):
        score = 0
        status = response_mock.get('status', 200)
        
        # 1. Server errors (Rất quan trọng)
        if status >= 500:
            score += 100
            
        # 2. Auth anomaly/bypass (Kiểm thử vi phạm quyền)
        if response_mock.get('auth_anomaly'):
            score += 80
            
        # 3. State Transitions (API có sinh ra/đổi state object mới không?)
        if response_mock.get('state_transition'):
            score += 40
            
        # 4. Rare response code (Mã trạng thái hiếm)
        if status not in self.common_statuses:
            score += 20
            
        # 5. Response mutation (Payload bất ngờ thay đổi cấu trúc)
        if response_mock.get('response_diff', False):
            score += 10
            
        # 6. Deeper workflows (Khuyến khích đào sâu vừa phải)
        score += min(depth, 10) * 2
        
        # 7. Invalid request penalty (Phạt lỗi cú pháp)
        if status == 400:
            score -= 10
            
        # 8. Exploration Bonus (UCT/MCTS): Thưởng cho các node ít được đi tới
        exploration_bonus = 50 / math.sqrt(visit_count) if visit_count > 0 else 50
        score += exploration_bonus
            
        return score

    def calculate_diversity_penalty(self, current_chain, current_beam):
        """Phạt điểm dựa trên Jaccard Similarity để đảm bảo Beam luôn đa dạng"""
        penalty = 0
        for b in current_beam:
            sim = jaccard_similarity(current_chain, b['chain'])
            # Nếu độ giống nhau > 60%, tiến hành phạt tỉ lệ thuận với độ giống nhau
            if sim > 0.6:
                penalty += 50 * sim
        return penalty

class CoverageBucketManager:
    def __init__(self, top_k=5):
        self.top_k = top_k
        self.buckets = {
            'auth': [],
            'admin': [],
            'crud': [],
            'other': []
        }

    def categorize(self, api_id):
        # Fix: tách CamelCase rồi split theo delimiter — tránh substring false positive
        # Ví dụ: 'getpost_comments' không bị nhận nhầm là 'crud' do chứa 'post'
        expanded = re.sub(r'([a-z])([A-Z])', r'\1 \2', api_id)
        tokens = set(re.split(r'[_\-\s/]', expanded.lower()))
        if tokens & {'login', 'signup', 'auth', 'token', 'password'}:
            return 'auth'
        elif 'admin' in tokens:
            return 'admin'
        elif tokens & {'create', 'update', 'delete', 'post', 'put', 'add'}:
            return 'crud'
        else:
            return 'other'

    def add_to_bucket(self, chain, score, state=None):
        # Phân loại bucket dựa trên API cuối cùng trong chuỗi
        last_api = chain[-1]
        bucket_name = self.categorize(last_api)
        
        self.buckets[bucket_name].append({'chain': list(chain), 'score': score, 'state': state})
        # Sắp xếp giảm dần theo điểm và giữ lại Top-K
        self.buckets[bucket_name].sort(key=lambda x: x['score'], reverse=True)
        self.buckets[bucket_name] = self.buckets[bucket_name][:self.top_k]

    def get_all_beams(self):
        """Lấy tất cả các chuỗi từ tất cả các buckets"""
        all_beams = []
        for v in self.buckets.values():
            all_beams.extend(v)
        return all_beams

class HybridBeamFuzzer:
    def __init__(self, operations, adjacency_list, beam_width=5):
        self.operations = operations
        self.adjacency_list = adjacency_list
        self.scorer = HeuristicScorer()
        self.beam_width = beam_width # Top K cho mỗi bucket
        self.node_visit_count = {op['id']: 0 for op in self.operations} # Tracker cho Exploration Bonus
        self.executor = RequestExecutor() # Bộ thực thi thật (đang mock)

    def calculate_adaptive_bfs_threshold(self):
        """Tính toán độ sâu BFS tự thích ứng dựa vào độ dày đặc của đồ thị"""
        total_edges = sum(len(edges) for edges in self.adjacency_list.values())
        num_nodes = len(self.operations)
        branching_factor = total_edges / num_nodes if num_nodes > 0 else 0
        
        print(f"[*] Branching Factor trung bình: {branching_factor:.2f}")
        if branching_factor > 5:
            # Đồ thị quá dày, State Explosion dễ xảy ra, bật Beam sớm
            return 2
        elif branching_factor < 2:
            # Đồ thị quá thưa thớt, an toàn chạy BFS lâu hơn
            return 4
        else:
            return 3

    def run_fuzzer(self, max_depth=10):
        bfs_threshold = self.calculate_adaptive_bfs_threshold()
        print(f"[*] Adaptive BFS Threshold tính toán được: {bfs_threshold}")
        print(f"[*] Max Depth: {max_depth}, Beam Width per bucket: {self.beam_width}, BFS Cap: {MAX_BFS_BEAMS}")
        
        current_beams = []
        for op in self.operations:
            current_beams.append({
                'chain': [op['id']], 
                'score': 0,
                'state': StateStore()
            })
            self.node_visit_count[op['id']] += 1
            
        final_completed_chains = []

        for current_depth in range(2, max_depth + 1):
            print(f"\n[+] Đang khám phá ở độ sâu: {current_depth}")
            bucket_manager = CoverageBucketManager(top_k=self.beam_width)
            next_beams = []

            # Fix UCT: snapshot visit_count tại đầu mỗi depth level
            # Tránh việc cùng 1 node bị nhiều beam cộng dồn visit trong vòng lặp hiện tại
            # làm Exploration Bonus bị deflate sai
            visit_snapshot = dict(self.node_visit_count)

            for beam in current_beams:
                last_api_id = beam['chain'][-1]
                neighbors = self.adjacency_list.get(last_api_id, [])
                
                if not neighbors:
                    final_completed_chains.append(beam)
                    continue

                for edge in neighbors:
                    next_api = edge['to']
                    
                    if next_api in beam['chain']:
                        continue
                        
                    new_chain = list(beam['chain'])
                    new_chain.append(next_api)

                    # Dùng snapshot để tính UCT bonus — phản ánh đúng mức độ đã khám phá
                    # trước khi vòng lặp depth hiện tại bắt đầu
                    visit_for_score = visit_snapshot.get(next_api, 0)
                    self.node_visit_count[next_api] += 1  # cập nhật actual count sau
                    
                    new_state = beam['state'].clone()
                    response_mock = self.executor.execute_request(next_api, new_state)
                    
                    base_score = self.scorer.calculate_score(
                        response_mock, current_depth, max(1, visit_for_score)
                    )
                    total_score = beam['score'] + base_score
                    
                    new_beam_dict = {
                        'chain': new_chain, 
                        'score': total_score,
                        'state': new_state
                    }
                    
                    if current_depth > bfs_threshold:
                        # Beam Search: Jaccard Diversity Penalty (greedy MMR)
                        diversity_penalty = self.scorer.calculate_diversity_penalty(
                            new_chain, bucket_manager.get_all_beams()
                        )
                        new_beam_dict['score'] -= diversity_penalty
                        bucket_manager.add_to_bucket(new_chain, new_beam_dict['score'], new_state)
                    else:
                        next_beams.append(new_beam_dict)
            
            # Cập nhật danh sách Beam cho depth tiếp theo
            if current_depth > bfs_threshold:
                current_beams = bucket_manager.get_all_beams()
            else:
                # Fix BFS Memory Risk: giới hạn số beams để tránh bùng nổ O(BF^depth)
                if len(next_beams) > MAX_BFS_BEAMS:
                    next_beams.sort(key=lambda x: x['score'], reverse=True)
                    next_beams = next_beams[:MAX_BFS_BEAMS]
                    print(f"  [!] BFS Cap kích hoạt — cắt xuống còn {MAX_BFS_BEAMS} beams.")
                current_beams = next_beams
                
            print(f"  -> Giữ lại {len(current_beams)} chains tiềm năng nhất.")
            if not current_beams:
                break
                
        # Gom tất cả các chains còn tồn tại
        final_completed_chains.extend(current_beams)
        final_completed_chains.sort(key=lambda x: x['score'], reverse=True)
        return final_completed_chains

    def export_results(self, chains, output_file="beam_strategies.json"):
        """Xuất kết quả kèm metadata đầy đủ phục vụ phân tích nghiên cứu."""
        categorizer = CoverageBucketManager()
        output_data = {
            "total_strategies_found": len(chains),
            "top_strategies": []
        }
        for rank, chain in enumerate(chains):
            chain_list = chain["chain"]
            # Lấy state memory thay vì repr chuỗi để dễ parse sau
            state_memory = chain["state"].memory if hasattr(chain["state"], 'memory') else {}
            output_data["top_strategies"].append({
                "rank": rank + 1,
                "chain": chain_list,
                "depth": len(chain_list) - 1,          # Độ sâu = số API calls - 1
                "bucket": categorizer.categorize(chain_list[-1]),  # Phân loại theo API cuối
                "score": round(chain["score"], 4),
                "captured_state": state_memory         # Token/ID thực tế thu được
            })
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        print(f"\n[*] Đã xuất kết quả {len(chains)} chiến lược tốt nhất ra file {output_file}.")