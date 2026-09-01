import json

from generate_report import _aggregate_findings, _group_apis_by_outcome, generate_html_report
from knowledge_memory import KnowledgeMemory


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
    )

    output_file = tmp_path / "beam.json"
    memory.export(str(output_file))
    request = json.loads(output_file.read_text(encoding="utf-8"))["endpoint_stats"][
        "getOrder"
    ]["all_requests"][0]

    assert request["sent_query"] == {"expand": "details"}
    assert request["sent_cookies"] == {"session": "private-session"}
    assert request["actor_id"] == "attacker-b"
    assert request["attack_metadata"]["baseline"]["body"]["orderId"] == "order-a"
    assert request["attack_metadata"]["attack"]["body"]["orderId"] == "order-b"
    assert request["sent_files"]["video"]["filename"] == "sample.mp4"


def test_html_report_explains_attack_and_redacts_secrets(tmp_path):
    input_file = tmp_path / "beam.json"
    output_dir = tmp_path / "report"
    data = {
        "summary": {"total_requests": 1},
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
