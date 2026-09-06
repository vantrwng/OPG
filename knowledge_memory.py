import json
import re
import time
from collections import deque
from response_outcome import evaluate_response


REDACTED_VALUE = "***REDACTED***"

_SENSITIVE_KEY_PARTS = {
    "authorization", "cookie", "cookies", "credential", "credentials",
    "password", "passwd", "passphrase",
    "secret", "session", "token", "apikey", "privatekey", "clientsecret",
    "accesstoken", "refreshtoken", "setcookie", "csrf", "xsrf",
}
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:authorization|proxy[-_ ]?authorization|access[-_ ]?token|"
    r"refresh[-_ ]?token|api[-_ ]?key|client[-_ ]?secret|private[-_ ]?key|"
    r"password|passwd|passphrase|cookie|session|credential|csrf|xsrf)\b\s*[:=]\s*)"
    r"([^\s,;&}]+)"
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+"
)


def _is_sensitive_key(key) -> bool:
    parts = re.findall(r"[a-z0-9]+", str(key or "").casefold())
    compact = "".join(parts)
    return bool(
        set(parts) & _SENSITIVE_KEY_PARTS
        or compact in _SENSITIVE_KEY_PARTS
        or any(
            compact.startswith(marker) or compact.endswith(marker)
            for marker in _SENSITIVE_KEY_PARTS
        )
    )


def _is_sensitive_container_key(key) -> bool:
    compact = "".join(re.findall(r"[a-z0-9]+", str(key or "").casefold()))
    return compact in _SENSITIVE_KEY_PARTS


def _sanitize_text(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        else:
            return json.dumps(
                sanitize_sensitive(parsed), ensure_ascii=False, separators=(",", ":")
            )

    sanitized = _SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{REDACTED_VALUE}", value
    )
    return _AUTH_SCHEME_RE.sub(
        lambda match: f"{match.group(1)} {REDACTED_VALUE}", sanitized
    )


def sanitize_sensitive(value, key: str = "", _force: bool = False):
    """Return a JSON-safe copy with credential-bearing values removed."""
    force = _force or _is_sensitive_key(key)
    if isinstance(value, dict):
        child_force = _force or _is_sensitive_container_key(key)
        return {
            child_key: sanitize_sensitive(child, str(child_key), child_force)
            for child_key, child in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_sensitive(child, key, force) for child in value]
    if force:
        return value if isinstance(value, bool) else REDACTED_VALUE
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


def _transport_was_attempted(status, elapsed_ms=None, explicit=None) -> bool:
    """Distinguish an HTTP attempt from a local diagnostic event."""
    if explicit is not None:
        return bool(explicit)
    try:
        if int(status) > 0:
            return True
    except (TypeError, ValueError):
        pass
    return isinstance(elapsed_ms, (int, float))


class KnowledgeMemory:
    """
    Lưu trữ kiến thức trong thời gian chạy (Runtime state), 
    thu thập thống kê chi tiết, và xuất báo cáo.
    """
    # Giới hạn tối đa để tránh OOM khi chạy lâu trên API lớn
    _MAX_HISTORY       = 10_000  # Tổng request history giữ lại
    _MAX_PER_ENDPOINT  = 200     # Tối đa request/endpoint trong endpoint_stats

    def __init__(self, started_at_monotonic=None, started_at_epoch=None):
        self._run_started_at = (
            float(started_at_monotonic)
            if started_at_monotonic is not None else time.perf_counter()
        )
        self._run_started_epoch = (
            float(started_at_epoch)
            if started_at_epoch is not None else time.time()
        )
        self._run_finished_at = None
        self._run_finished_epoch = None
        self.found_vulnerabilities = set() # Set cho fast lookup f"{api_id}:{status}"
        self.node_visit_count = {}
        self.top_strategies = []
        
        # Thống kê mở rộng
        self.request_history: deque = deque(maxlen=self._MAX_HISTORY)  # bounded
        self._request_event_count = 0
        self._http_request_count = 0
        self.findings = []
        self.security_observations = []
        self._security_observation_index = {}
        self.endpoint_stats = {}
        self.edge_feedback = {}
        self.pipeline_summary = {}
        self.auth_bootstrap = []
        self.replay_recipes = []
        self.experiment_coverage = {}
        self.bola_ground_truth = {}
        self.security_metrics = {}

    def mark_endpoint_discovered(self, api_id: str, reason: str = "OpenAPI operation"):
        record = self.experiment_coverage.setdefault(api_id, {
            "endpoint_discovered": True,
            "experiments_generated": 0,
            "experiments_executed": 0,
            "experiments_verifiable": 0,
            "findings_confirmed": 0,
            "events": [],
        })
        record["endpoint_discovered"] = True
        if reason and not record["events"]:
            record["events"].append({"stage": "discovered", "reason": reason})

    def record_experiment_stage(
        self, api_id: str, stage: str, reason: str = "", count: int = 1,
        status: str = "",
    ):
        self.mark_endpoint_discovered(api_id)
        record = self.experiment_coverage[api_id]
        counters = {
            "generated": "experiments_generated",
            "executed": "experiments_executed",
            "verifiable": "experiments_verifiable",
            "confirmed": "findings_confirmed",
        }
        if stage in counters:
            record[counters[stage]] += max(0, int(count))
        record["events"].append({
            "stage": stage, "status": status or stage,
            "reason": str(reason or ""), "count": max(0, int(count)),
        })

    def set_bola_ground_truth(self, ground_truth):
        """Set endpoint-level BOLA labels for reproducible evaluation.

        Accepted forms are ``{"getOrder": true}`` or a list of vulnerable
        endpoint IDs. Labels are intentionally endpoint-level so a benchmark
        can be compared with the confirmed findings without guessing from
        HTTP status codes.
        """
        if isinstance(ground_truth, list):
            ground_truth = {str(api_id): True for api_id in ground_truth}
        if not isinstance(ground_truth, dict):
            raise ValueError("BOLA ground truth must be an object or list")
        normalized = {}
        for api_id, label in ground_truth.items():
            if isinstance(label, dict):
                label = label.get("bola", label.get("vulnerable", False))
            normalized[str(api_id)] = bool(label)
        self.bola_ground_truth = normalized

    @staticmethod
    def _metric_ratio(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else None

    def compute_bola_metrics(self):
        """Compute coverage and endpoint-level precision/recall/F1."""
        confirmed = {
            str(item.get("api", ""))
            for item in self.findings
            if str(item.get("type", "")).upper() == "BOLA"
        }
        endpoint_ids = set(self.experiment_coverage) | set(self.bola_ground_truth)
        per_endpoint = {}
        totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for api_id in sorted(endpoint_ids):
            expected = bool(self.bola_ground_truth.get(api_id, False))
            predicted = api_id in confirmed
            tp = int(expected and predicted)
            fp = int(not expected and predicted)
            fn = int(expected and not predicted)
            tn = int(not expected and not predicted)
            for key, value in (("tp", tp), ("fp", fp), ("fn", fn), ("tn", tn)):
                totals[key] += value
            coverage = dict(self.experiment_coverage.get(api_id, {}))
            generated = int(coverage.get("experiments_generated", 0) or 0)
            executed = int(coverage.get("experiments_executed", 0) or 0)
            verifiable = int(coverage.get("experiments_verifiable", 0) or 0)
            coverage.update({
                "ground_truth_bola": expected if api_id in self.bola_ground_truth else None,
                "predicted_bola": predicted,
                "coverage_rate": self._metric_ratio(executed, generated),
                "verifiable_rate": self._metric_ratio(verifiable, executed),
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": self._metric_ratio(tp, tp + fp),
                "recall": self._metric_ratio(tp, tp + fn),
                "f1": self._metric_ratio(2 * tp, 2 * tp + fp + fn),
            })
            per_endpoint[api_id] = coverage

        self.security_metrics = {
            "ground_truth_available": bool(self.bola_ground_truth),
            "per_endpoint": per_endpoint,
            "overall": {
                **totals,
                "precision": self._metric_ratio(totals["tp"], totals["tp"] + totals["fp"]),
                "recall": self._metric_ratio(totals["tp"], totals["tp"] + totals["fn"]),
                "f1": self._metric_ratio(
                    2 * totals["tp"],
                    2 * totals["tp"] + totals["fp"] + totals["fn"],
                ),
            },
        }
        return self.security_metrics

    def record_visit(self, api_id: str):
        if api_id not in self.node_visit_count:
            self.node_visit_count[api_id] = 0
            self.endpoint_stats.setdefault(
                api_id, {"visits": 0, "status_counts": {}, "all_requests": []}
            )
            self.endpoint_stats[api_id].setdefault("visits", 0)
            self.endpoint_stats[api_id].setdefault("status_counts", {})
            self.endpoint_stats[api_id].setdefault("all_requests", [])
        self.node_visit_count[api_id] += 1
        self.endpoint_stats[api_id]["visits"] += 1

    def get_visit_count(self, api_id: str) -> int:
        return self.node_visit_count.get(api_id, 0)

    def record_request(
        self,
        api_id: str,
        method: str,
        path: str,
        status: int,
        chain: list = None,
        response_text: str = None,
        request_payload: dict = None,
        payload_source: str = "NONE",
        repair_reason: str = "",
        repair_history: list = None,
        sent_headers: dict = None,
        sent_query: dict = None,
        sent_cookies: dict = None,
        actor_id: str = "",
        attack_metadata: dict = None,
        successful: bool = None,
        outcome_reason: str = "",
        auth_recovery: dict = None,
        auth_context: dict = None,
        sent_files: dict = None,
        elapsed_ms: float = None,
        transport_attempted: bool = None,
    ):
        if api_id not in self.endpoint_stats:
            self.endpoint_stats[api_id] = {"visits": 0, "status_counts": {}, "all_requests": []}
        
        stats = self.endpoint_stats[api_id]["status_counts"]
        all_requests = self.endpoint_stats[api_id].setdefault("all_requests", [])
        status_str = str(status)
        stats[status_str] = stats.get(status_str, 0) + 1
        
        # Giới hạn số lượng request lưu trữ per-endpoint để tránh OOM
        if len(all_requests) >= self._MAX_PER_ENDPOINT:
            all_requests.pop(0)  # Xóa record cũ nhất
        
        outcome = evaluate_response(status, response_text=response_text or "")
        effective_success = outcome.successful if successful is None else bool(successful)
        effective_reason = outcome_reason or outcome.reason
        was_attempted = _transport_was_attempted(
            status, elapsed_ms=elapsed_ms, explicit=transport_attempted
        )

        try:
            is_http_2xx = 200 <= int(status) < 300
        except (TypeError, ValueError):
            is_http_2xx = False

        request_record = {
            "method": method,
            "path": path,
            "status": status_str,
            "request_payload": request_payload if request_payload is not None else {},
            "response_text": response_text if response_text is not None else "",
            "payload_source": payload_source,
            "repair_reason": repair_reason,
            "repair_history": repair_history if repair_history is not None else [],
            "sent_headers": sent_headers if sent_headers is not None else {},
            "sent_query": sent_query if sent_query is not None else {},
            "sent_cookies": sent_cookies if sent_cookies is not None else {},
            "actor_id": actor_id,
            "attack_metadata": attack_metadata if attack_metadata is not None else {},
            "successful": effective_success,
            "semantic_failure": is_http_2xx and not effective_success,
            "outcome_reason": effective_reason,
            "auth_recovery": auth_recovery if auth_recovery is not None else {},
            "auth_context": auth_context if auth_context is not None else {},
            "sent_files": sent_files if sent_files is not None else {},
            "elapsed_ms": elapsed_ms,
            "transport_attempted": was_attempted,
            "chain": chain if chain is not None else []
        }
        all_requests.append(sanitize_sensitive(request_record))
        
        self.request_history.append(sanitize_sensitive({
            "api_id": api_id,
            "method": method,
            "path": path,
            "status": status,
            "chain_length": len(chain) if chain else 0,
            "transport_attempted": was_attempted,
            "timestamp": time.time()
        }))
        self._request_event_count += 1
        if was_attempted:
            self._http_request_count += 1

    def record_finding(self, finding: dict):
        self.findings.append(sanitize_sensitive(finding))

    def record_security_observation(self, observation: dict):
        """Store suspected/inconclusive authorization evidence separately."""
        sanitized = sanitize_sensitive(observation)
        identity = {
            key: value for key, value in sanitized.items()
            if key not in {"occurrences", "variants"}
        }
        identity_key = json.dumps(identity, sort_keys=True, ensure_ascii=False)
        existing = self._security_observation_index.get(identity_key)
        if existing is not None:
            existing["occurrences"] = int(existing.get("occurrences", 1)) + int(
                sanitized.get("occurrences", 1)
            )
            return
        self.security_observations.append(sanitized)
        self._security_observation_index[identity_key] = sanitized

    def record_replay_recipe(self, recipe: dict):
        """Persist only structural replay data; runtime credentials/IDs are forbidden."""
        allowed = {
            "endpoint_relationship", "resource_type", "selector_field",
            "operation", "actor_relationship",
        }
        safe = sanitize_sensitive({key: recipe[key] for key in allowed if key in recipe})
        if safe and safe not in self.replay_recipes:
            self.replay_recipes.append(safe)
        
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
        self.top_strategies.append(sanitize_sensitive(strategy))

    def set_top_strategies(self, strategies: list):
        self.top_strategies = sanitize_sensitive(strategies or [])

    def set_pipeline_summary(self, summary: dict):
        self.pipeline_summary = sanitize_sensitive(dict(summary or {}))

    def set_auth_bootstrap(self, events: list):
        """Store setup evidence separately from fuzzing requests/findings."""
        self.auth_bootstrap = sanitize_sensitive(
            [dict(event) for event in (events or [])]
        )

    def finish_timer(self):
        """Freeze pipeline timing immediately before report serialization."""
        self._run_finished_at = time.perf_counter()
        self._run_finished_epoch = time.time()

    def export(self, output_file: str):
        # Tổng hợp thống kê
        self.compute_bola_metrics()
        total_requests = self._http_request_count
        total_request_events = self._request_event_count
        server_errors = sum(1 for f in self.findings if f.get("type") == "Crash/500")
        auth_anomalies = sum(1 for f in self.findings if f.get("type") == "Auth Anomaly")
        elapsed_values = [
            req.get("elapsed_ms")
            for stats in self.endpoint_stats.values()
            for req in stats.get("all_requests", [])
            if req.get("transport_attempted", True)
            if isinstance(req.get("elapsed_ms"), (int, float))
        ]
        observation_occurrences = sum(
            max(1, int(item.get("occurrences", 1) or 1))
            for item in self.security_observations
        )
        finished_at = self._run_finished_at or time.perf_counter()
        finished_epoch = self._run_finished_epoch or time.time()
        run_elapsed_ms = round((finished_at - self._run_started_at) * 1000, 2)
        
        output_data = {
            "summary": {
                "total_requests": total_requests,
                "total_request_events": total_request_events,
                "server_errors_500": server_errors,
                "auth_anomalies": auth_anomalies,
                "total_strategies_found": len(self.top_strategies),
                "total_findings": len(self.findings),
                "security_observations": len(self.security_observations),
                "security_observation_occurrences": observation_occurrences,
                "auth_bootstrap_requests": len(self.auth_bootstrap),
                "run_elapsed_ms": run_elapsed_ms,
                "run_started_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%S%z", time.localtime(self._run_started_epoch)
                ),
                "run_finished_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%S%z", time.localtime(finished_epoch)
                ),
                "total_http_elapsed_ms": round(sum(elapsed_values), 2),
                "average_http_elapsed_ms": (
                    round(sum(elapsed_values) / len(elapsed_values), 2)
                    if elapsed_values else None
                ),
            },
            "endpoint_stats": self.endpoint_stats,
            "edge_feedback": self.edge_feedback,
            "findings": self.findings,
            "security_observations": self.security_observations,
            "top_strategies": self.top_strategies,
            "pipeline_summary": self.pipeline_summary,
            "auth_bootstrap": self.auth_bootstrap,
            "replay_recipes": self.replay_recipes,
            "experiment_coverage": self.experiment_coverage,
            "security_metrics": self.security_metrics,
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sanitize_sensitive(output_data), f, indent=4, ensure_ascii=False)
        print(f"[*] Đã xuất {len(self.top_strategies)} chiến thuật tối ưu và {len(self.findings)} findings ra file {output_file}")
