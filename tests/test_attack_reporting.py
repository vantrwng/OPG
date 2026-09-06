import json

from generate_report import (
    _aggregate_findings,
    _aggregate_security_observations,
    _aggregate_suspected_bola_observations,
    _group_apis_by_outcome,
    generate_html_report,
)
from knowledge_memory import KnowledgeMemory, sanitize_sensitive


def test_bola_metrics_include_endpoint_coverage_and_ground_truth_scores():
    memory = KnowledgeMemory()
    memory.mark_endpoint_discovered("getVulnerable")
    memory.record_experiment_stage("getVulnerable", "generated", count=2)
    memory.record_experiment_stage("getVulnerable", "executed", count=2)
    memory.record_experiment_stage("getVulnerable", "verifiable", count=2)
    memory.record_experiment_stage("getVulnerable", "confirmed", count=1)
    memory.mark_endpoint_discovered("getSecure")
    memory.record_experiment_stage("getSecure", "generated", count=1)
    memory.record_experiment_stage("getSecure", "executed", count=1)
    memory.set_bola_ground_truth({"getVulnerable": True, "getSecure": False})
    memory.record_finding({"api": "getVulnerable", "type": "BOLA"})

    metrics = memory.compute_bola_metrics()

    assert metrics["overall"]["precision"] == 1.0
    assert metrics["overall"]["recall"] == 1.0
    assert metrics["per_endpoint"]["getVulnerable"]["coverage_rate"] == 1.0
    assert metrics["per_endpoint"]["getSecure"]["predicted_bola"] is False


def _attack_metadata():
    return {
        "strategy": "id_substitution",
        "technique": "foreign_resource_id",
        "description": "Thay orderId của owner bằng orderId thuộc actor khác",
        "owner_actor_id": "owner-a",
        "attacker_actor_id": "attacker-b",
        "baseline": {
            "path": "https://target.test/orders/order-a",
            "body": {"orderId": "order-a", "secret": "owner-secret-value"},
            "query": {"expand": "summary"},
        },
        "attack": {
            "path": "https://target.test/orders/order-b",
            "body": {"orderId": "order-b", "secret": "owner-secret-value"},
            "query": {"expand": "details"},
        },
        "mutation": {
            "field": "orderId",
            "original_id": "order-a",
            "substitute_id": "order-b",
        },
    }


def test_attack_transport_and_metadata_are_exported(tmp_path):
    memory = KnowledgeMemory()
    memory.record_request(
        api_id="getOrder",
        method="GET",
        path="https://target.test/orders/order-b",
        status=200,
        request_payload={"orderId": "order-b"},
        payload_source="ATTACKER_ID_SUBSTITUTION",
        sent_headers={"Authorization": "Bearer very-secret-token"},
        sent_query={"expand": "details"},
        sent_cookies={"session": "private-session"},
        actor_id="attacker-b",
        attack_metadata=_attack_metadata(),
        sent_files={"video": {
            "filename": "sample.mp4", "content_type": "video/mp4",
            "size": 32, "sha256": "abc123", "source": "BUILTIN_FIXTURE",
        }},
        elapsed_ms=123.45,
    )

    output_file = tmp_path / "beam.json"
    memory.export(str(output_file))
    request = json.loads(output_file.read_text(encoding="utf-8"))["endpoint_stats"][
        "getOrder"
    ]["all_requests"][0]

    assert request["sent_query"] == {"expand": "details"}
    assert request["sent_cookies"] == {"session": "***REDACTED***"}
    assert request["sent_headers"]["Authorization"] == "***REDACTED***"
    assert request["actor_id"] == "attacker-b"
    assert request["attack_metadata"]["baseline"]["body"]["orderId"] == "order-a"
    assert request["attack_metadata"]["attack"]["body"]["orderId"] == "order-b"
    assert request["sent_files"]["video"]["filename"] == "sample.mp4"
    assert request["elapsed_ms"] == 123.45
    assert json.loads(output_file.read_text(encoding="utf-8"))["summary"]["run_elapsed_ms"] >= 0
    assert json.loads(output_file.read_text(encoding="utf-8"))["summary"]["average_http_elapsed_ms"] == 123.45
    serialized = output_file.read_text(encoding="utf-8")
    assert "very-secret-token" not in serialized
    assert "private-session" not in serialized


def test_pipeline_timer_uses_process_start_and_freezes_at_finish(tmp_path, monkeypatch):
    memory = KnowledgeMemory(started_at_monotonic=100.0, started_at_epoch=1_700_000_000)
    monkeypatch.setattr("knowledge_memory.time.perf_counter", lambda: 3700.0)
    monkeypatch.setattr("knowledge_memory.time.time", lambda: 1_700_003_600)
    memory.finish_timer()
    # A later export must retain the frozen one-hour pipeline duration.
    monkeypatch.setattr("knowledge_memory.time.perf_counter", lambda: 9999.0)
    output_file = tmp_path / "timing.json"
    memory.export(str(output_file))
    summary = json.loads(output_file.read_text(encoding="utf-8"))["summary"]
    assert summary["run_elapsed_ms"] == 3_600_000
    assert summary["run_started_at"]
    assert summary["run_finished_at"]


def test_replay_recipe_exports_only_structural_relationship(tmp_path):
    memory = KnowledgeMemory()
    memory.record_replay_recipe({
        "endpoint_relationship": {"create": "createMemo", "target": "getMemo"},
        "resource_type": "memo", "selector_field": "memoId",
        "operation": "GET", "actor_relationship": "same_role_distinct_principals",
        "token": "must-not-export", "resource_id": "runtime-id",
    })
    output_file = tmp_path / "beam.json"
    memory.export(str(output_file))
    recipe = json.loads(output_file.read_text(encoding="utf-8"))["replay_recipes"][0]
    assert recipe["resource_type"] == "memo"
    assert "token" not in recipe
    assert "resource_id" not in recipe


def test_html_report_explains_attack_and_redacts_secrets(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    data = {
        "summary": {
            "total_requests": 1,
            "run_elapsed_ms": 62500,
            "average_http_elapsed_ms": 123.45,
        },
        "findings": [],
        "top_strategies": [],
        "endpoint_stats": {
            "getOrder": {
                "visits": 1,
                "status_counts": {"200": 1},
                "all_requests": [{
                    "method": "GET",
                    "path": "https://target.test/orders/order-b",
                    "status": "200",
                    "request_payload": {
                        "orderId": "order-b",
                        "secret": "owner-secret-value",
                    },
                    "response_text": '{"id":"order-b"}',
                    "payload_source": "ATTACKER_ID_SUBSTITUTION",
                    "sent_headers": {"Authorization": "Bearer very-secret-token"},
                    "sent_query": {"expand": "details"},
                    "sent_cookies": {"session": "private-session"},
                    "actor_id": "attacker-b",
                    "attack_metadata": _attack_metadata(),
                    "chain": ["listOrders", "getOrder"],
                    "elapsed_ms": 123.45,
                }],
            }
        },
    }
    input_file.write_text(json.dumps(data), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert "Cách tấn công" in report
    assert "Thay thế định danh (BOLA/IDOR)" in report
    assert "owner-a → attacker-b" in report
    assert "body.orderId" in report
    assert "order-a" in report and "order-b" in report
    assert "Query thực gửi" in report
    assert "very-secret-token" not in report
    assert "owner-secret-value" not in report
    assert "private-session" not in report
    assert "Tổng thời gian chạy" in report
    assert "1 phút 2.5 giây" in report
    assert "HTTP trung bình" in report
    assert "123 ms" in report


def test_api_grouping_prioritizes_any_2xx_over_5xx():
    success, failed = _group_apis_by_outcome({
        "eventuallyWorks": {"status_counts": {"500": 3, "200": 1}},
        "alwaysCrashes": {"status_counts": {"500": 4}},
        "clientRejected": {"status_counts": {"400": 2, "404": 1}},
    })

    assert success == ["eventuallyWorks"]
    assert failed == ["alwaysCrashes", "clientRejected"]


def test_api_grouping_treats_annotated_http_200_fail_as_failed():
    success, failed = _group_apis_by_outcome({
        "businessFailure": {
            "status_counts": {"200": 3},
            "all_requests": [
                {"status": "200", "successful": False, "semantic_failure": True},
            ],
        },
        "mixedOutcome": {
            "status_counts": {"200": 2},
            "all_requests": [
                {"status": "200", "successful": False},
                {"status": "200", "successful": True},
            ],
        },
    })

    assert success == ["mixedOutcome"]
    assert failed == ["businessFailure"]


def test_security_probe_does_not_inflate_valid_workflow_rate():
    success, failed = _group_apis_by_outcome({
        "attackOnlySuccess": {
            "status_counts": {"200": 1, "403": 1},
            "all_requests": [
                {"status": "403", "successful": False, "payload_source": "HEURISTIC"},
                {"status": "200", "successful": True,
                 "payload_source": "ATTACKER_ID_SUBSTITUTION"},
            ],
        },
        "validBaseline": {
            "status_counts": {"204": 1, "403": 1},
            "all_requests": [
                {"status": "204", "successful": True, "payload_source": "HEURISTIC"},
                {"status": "403", "successful": False,
                 "payload_source": "ATTACKER_REFERENCE_FORGE"},
            ],
        },
    })

    assert success == ["validBaseline"]
    assert failed == ["attackOnlySuccess"]


def test_report_aggregates_finding_variants_by_api_method_and_type():
    findings = [
        {
            "api": "getUser",
            "method": "GET",
            "path": f"/users/{index}",
            "type": "authorization_issue",
            "strategy": f"variant-{index}",
        }
        for index in range(5)
    ]

    aggregated = _aggregate_findings(findings)

    assert len(aggregated) == 1
    assert aggregated[0]["variant_count"] == 5
    assert len(aggregated[0]["variants"]) == 5


def test_report_renders_bootstrap_separately_and_keeps_secrets_redacted(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    input_file.write_text(json.dumps({
        "summary": {"total_requests": 0, "total_findings": 0},
        "endpoint_stats": {},
        "findings": [],
        "top_strategies": [],
        "pipeline_summary": {
            "phase_0": {"completed": True, "events": 1},
        },
        "auth_bootstrap": [{
            "stage": "signup",
            "actor_id": "principal-a",
            "method": "POST",
            "path": "https://target.test/register",
            "status": 201,
            "successful": True,
            "request_payload": {
                "login": "principal-a",
                "password": "never-display-this",
            },
            "response_body": {"accessLevel": "effective-tier"},
            "requested_role": "requested-tier",
            "effective_role": "effective-tier",
            "auth_transports": [{
                "kind": "cookie", "name": "session_id", "present": True,
            }],
        }],
    }), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert "Authentication Bootstrap (1)" in report
    assert "requested-tier" in report
    assert "effective-tier" in report
    assert "cookie:session_id" in report
    assert "never-display-this" not in report


def test_report_marks_unreached_phases_as_not_run(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    input_file.write_text(json.dumps({
        "summary": {"total_requests": 0, "total_findings": 0},
        "endpoint_stats": {},
        "findings": [],
        "pipeline_summary": {
            "mode": "security",
            "phase_0": {"completed": False, "events": 2},
        },
    }), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert "PHASE 1 — Valid workflow</div>" in report
    assert "Chưa chạy · 0 baseline hợp lệ" in report
    assert "PHASE 2 — Security validation</div>" in report
    assert "Chưa chạy</div>" in report


def test_export_redacts_response_repair_history_and_captured_state(tmp_path):
    memory = KnowledgeMemory()
    memory.record_request(
        api_id="login",
        method="POST",
        path="https://target.test/login",
        status=200,
        request_payload={"password": "request-password"},
        response_text=json.dumps({"access_token": "response-token"}),
        repair_history=[{
            "payload": {"passphrase": "repair-password"},
            "response": json.dumps({"session": "repair-session"}),
        }],
    )
    memory.set_top_strategies([{
        "chain": ["login"],
        "captured_state": {"refresh_token": "captured-token"},
    }])

    output_file = tmp_path / "beam.json"
    memory.export(str(output_file))
    serialized = output_file.read_text(encoding="utf-8")

    for secret in (
        "request-password", "response-token", "repair-password",
        "repair-session", "captured-token",
    ):
        assert secret not in serialized


def test_operation_id_containing_password_does_not_redact_diagnostic_subtree():
    sanitized = sanitize_sensitive({
        "api_views.users.update_password": {
            "status": 204, "count": 2, "path": "/users/alice/password",
            "password": "must-hide",
        }
    })

    record = sanitized["api_views.users.update_password"]
    assert record["status"] == 204
    assert record["count"] == 2
    assert record["path"] == "/users/alice/password"
    assert record["password"] == "***REDACTED***"


def test_export_counts_only_attempted_http_requests_and_deduplicates_observations(tmp_path):
    memory = KnowledgeMemory()
    memory.record_request(
        api_id="getUser", method="GET", path="/users/alice", status=0,
        response_text="Unsupported method for body mutation",
        payload_source="LOCAL_MUTATOR", transport_attempted=False,
    )
    memory.record_request(
        api_id="getUser", method="GET", path="/users/alice", status=200,
        response_text='{"username":"alice"}', elapsed_ms=12.5,
    )
    observation = {
        "classification": "UNVERIFIED", "api": "getUser", "type": "BOLA",
        "reasoning": "identifier ownership is unknown",
    }
    memory.record_security_observation(observation)
    memory.record_security_observation(observation)

    output_file = tmp_path / "beam.json"
    memory.export(str(output_file))
    exported = json.loads(output_file.read_text(encoding="utf-8"))

    assert exported["summary"]["total_requests"] == 1
    assert exported["summary"]["total_request_events"] == 2
    assert exported["summary"]["security_observations"] == 1
    assert exported["summary"]["security_observation_occurrences"] == 2
    assert exported["security_observations"][0]["occurrences"] == 2


def test_observation_aggregation_preserves_distinct_evidence_and_counts_repeats():
    observations = [
        {"classification": "SUSPECTED", "api": "getUser", "type": "BOLA",
         "evidence": ["foreign owner"]},
        {"classification": "SUSPECTED", "api": "getUser", "type": "BOLA",
         "evidence": ["foreign owner"]},
        {"classification": "SUSPECTED", "api": "getUser", "type": "BOLA",
         "evidence": ["different fingerprint"]},
    ]

    aggregated = _aggregate_security_observations(observations)

    assert len(aggregated) == 2
    assert sorted(item["occurrences"] for item in aggregated) == [1, 2]


def test_suspected_bola_cards_group_by_api_method_and_type():
    aggregated = _aggregate_suspected_bola_observations([
        {"classification": "SUSPECTED", "api": "getMemo", "method": "GET",
         "type": "BOLA", "confidence": 0.55, "occurrences": 2,
         "evidence": ["foreign id"], "strategy": "id_substitution"},
        {"classification": "SUSPECTED", "api": "getMemo", "method": "GET",
         "type": "BOLA", "confidence": 0.45, "evidence": ["response differs"],
         "strategy": "reference_forge"},
        {"classification": "SUSPECTED", "api": "patchMemo", "method": "PATCH",
         "type": "BOLA", "confidence": 0.55, "evidence": ["foreign owner"]},
    ])

    assert len(aggregated) == 2
    get_memo = next(item for item in aggregated if item["api"] == "getMemo")
    assert get_memo["occurrences"] == 3
    assert len(get_memo["variants"]) == 2
    assert get_memo["evidence"] == ["foreign id", "response differs"]
    assert get_memo["confidence"] == 0.55


def test_report_renders_suspected_and_unverified_observations(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    input_file.write_text(json.dumps({
        "summary": {"total_requests": 0}, "endpoint_stats": {},
        "findings": [], "top_strategies": [],
        "security_observations": [
            {"classification": "SUSPECTED", "api": "patchShortcut", "type": "BOLA",
             "confidence": 0.78, "status": 200,
             "evidence": ["foreign object returned"]},
            {"classification": "UNVERIFIED", "api": "getUser", "type": "BOLA",
             "reasoning": "identifier was guessed"},
        ],
    }), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert "Tín hiệu cần xác minh (1)" in report
    assert "SUSPECTED" in report and "UNVERIFIED" in report
    assert "BOLA/IDOR" in report and "patchShortcut" in report and "getUser" in report
    assert "Độ tin cậy: 55%" in report
    assert "HTTP 200" in report


def test_report_renders_bola_coverage_and_benchmark_metrics(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    input_file.write_text(json.dumps({
        "summary": {"total_requests": 0}, "endpoint_stats": {},
        "findings": [], "top_strategies": [], "security_observations": [],
        "security_metrics": {
            "ground_truth_available": True,
            "overall": {"precision": 1.0, "recall": 0.5, "f1": 0.6667},
            "per_endpoint": {
                "getOrder": {
                    "experiments_generated": 2,
                    "experiments_executed": 2,
                    "coverage_rate": 1.0,
                    "verifiable_rate": 0.5,
                    "precision": 1.0,
                    "recall": 0.5,
                    "f1": 0.6667,
                },
            },
        },
    }), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert "BOLA coverage và benchmark" in report
    assert "getOrder" in report
    assert "100.0%" in report


def test_report_recomputes_legacy_http_count_and_uses_consistent_finding_labels(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    input_file.write_text(json.dumps({
        "summary": {"total_requests": 3},
        "endpoint_stats": {"debugUsers": {"all_requests": [
            {"status": "0", "response_text": "Unsupported method for body mutation"},
            {"status": "200", "elapsed_ms": 10},
            {"status": "500", "elapsed_ms": 11},
        ]}},
        "findings": [{
            "api": "debugUsers", "method": "GET", "status": 200,
            "type": "EXCESSIVE_DATA_EXPOSURE",
        }],
        "security_observations": [
            {"classification": "UNVERIFIED", "api": "getUser", "type": "BOLA"},
            {"classification": "UNVERIFIED", "api": "getUser", "type": "BOLA"},
            {"classification": "SUSPECTED", "api": "getUser",
             "method": "GET", "type": "MASS_ASSIGNMENT"},
        ],
        "top_strategies": [],
    }), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert '>2</div>\n        <div class="stat-label">Request kiểm thử đã gửi</div>' in report
    assert "Tín hiệu cần xác minh (1 nhóm / 2 lần kiểm thử)" in report
    assert "MASS_ASSIGNMENT" not in report
    assert "Lộ dữ liệu nhạy cảm" in report
    assert "BOLA — Lộ dữ liệu" not in report


def test_report_does_not_embed_operation_id_in_inline_javascript(tmp_path):
    malicious_id = "x');alert('stored-xss')//"
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    input_file.write_text(json.dumps({
        "summary": {"total_requests": 0},
        "endpoint_stats": {
            malicious_id: {"visits": 0, "status_counts": {}, "all_requests": []},
        },
        "findings": [{"api": malicious_id, "type": "BOLA", "status": 200}],
        "top_strategies": [{"chain": [malicious_id], "score": 1}],
    }), encoding="utf-8")

    generate_html_report(str(input_file), str(output_dir))
    report = (output_dir / "index.html").read_text(encoding="utf-8")

    assert "onclick=\"showApi(" not in report
    assert "onclick='showApi(" not in report
    assert "class=\"api-link\"" in report or "class='api-link'" in report
    assert "data-api-id=" in report
