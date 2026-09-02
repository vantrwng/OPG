from unittest.mock import MagicMock

from knowledge_memory import KnowledgeMemory
from test_strategy_engine import TestStrategyEngine
from state_store import StateStore


def test_workflow_mode_disables_attack_agents_by_default():
    engine = TestStrategyEngine(
        operations=[],
        adjacency_list={},
        request_executor=MagicMock(),
        graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
    )

    assert engine.enable_security_testing is False
    assert engine._attacker is None
    assert engine._auditor is None


def test_security_phase_consumes_only_frozen_valid_baselines():
    engine = TestStrategyEngine(
        operations=[],
        adjacency_list={},
        request_executor=MagicMock(),
        graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
        enable_security_testing=True,
    )
    engine._attacker = MagicMock()
    engine._auditor = MagicMock()
    engine._run_local_mutator_security_case = MagicMock()
    engine._run_3agent_pipeline = MagicMock(return_value=0.0)
    state = StateStore({"actor_id": "owner-a", "auth_token": "token-a"})
    baseline = {
        "status": 200,
        "successful": True,
        "url": "https://target.test/orders/order-a",
        "sent_payload": {"orderId": "order-a"},
        "raw_response": {"id": "order-a"},
    }
    engine.executor.execute_request.return_value = baseline
    node = {
        "id": "getOrder",
        "method": "GET",
        "path": "/orders/{orderId}",
    }

    engine._capture_valid_workflow(node, state, baseline, ["createOrder", "getOrder"])
    assert engine.get_valid_workflow_count() == 1

    summary = engine.run_security_phase()

    assert summary["baselines"] == 1
    assert summary["tested_endpoints"] == 1
    engine._run_local_mutator_security_case.assert_called_once()
    engine._run_3agent_pipeline.assert_called_once()


def test_security_phase_skips_auth_lifecycle_endpoints():
    engine = TestStrategyEngine(
        operations=[],
        adjacency_list={},
        request_executor=MagicMock(),
        graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
        enable_security_testing=True,
    )
    engine._attacker = MagicMock()
    engine._auditor = MagicMock()
    engine._run_3agent_pipeline = MagicMock()
    engine._capture_valid_workflow(
        {"id": "loginUser", "method": "POST", "path": "/auth/login"},
        StateStore({"actor_id": "owner-a"}),
        {"status": 200, "successful": True, "raw_response": None},
        ["loginUser"],
    )

    summary = engine.run_security_phase()

    assert summary["tested_endpoints"] == 0
    assert summary["skipped_auth_lifecycle"] == 1
    engine._run_3agent_pipeline.assert_not_called()


def test_authenticated_workflow_does_not_execute_signup_again():
    executor = MagicMock()
    executor.execute_request.return_value = {
        "status": 200,
        "successful": True,
        "response_text": "{}",
        "sent_payload": {},
        "raw_response": None,
    }
    operations = [
        {"id": "POST__auth_signup", "method": "POST", "path": "/auth/signup"},
        {"id": "GET__status", "method": "GET", "path": "/status"},
    ]
    engine = TestStrategyEngine(
        operations=operations,
        adjacency_list={},
        request_executor=executor,
        graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
    )

    engine.run(
        max_depth=1,
        initial_state=StateStore({
            "actor_id": "owner-a",
            "auth_token": "token-a",
            "username": "owner-a",
            "password": "OwnerPass!",
        }),
    )

    executed_ids = [call.kwargs["api_node"]["id"] for call in executor.execute_request.call_args_list]
    assert executed_ids == ["GET__status"]


def test_workflow_phase_defers_delete_to_isolated_security_phase():
    executor = MagicMock()
    executor.execute_request.return_value = {
        "status": 200, "successful": True, "response_text": "{}",
        "sent_payload": {}, "raw_response": {},
    }
    operations = [
        {"id": "getMemo", "method": "GET", "path": "/memo/{memoId}"},
        {"id": "deleteMemo", "method": "DELETE", "path": "/memo/{memoId}"},
    ]
    engine = TestStrategyEngine(
        operations=operations, adjacency_list={"getMemo": [{
            "to": "deleteMemo", "max_confidence": 0.9,
        }]}, request_executor=executor, graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
    )

    engine.run(max_depth=2, initial_state=StateStore({"memoId": 1}))

    executed = [call.kwargs["api_node"]["id"] for call in executor.execute_request.call_args_list]
    assert executed == ["getMemo"]


def test_security_phase_skips_attack_when_baseline_replay_fails():
    executor = MagicMock()
    executor.execute_request.return_value = {
        "status": 404,
        "successful": False,
        "response_text": '{"status":"fail","message":"not found"}',
        "outcome_reason": "HTTP 404",
    }
    engine = TestStrategyEngine(
        operations=[],
        adjacency_list={},
        request_executor=executor,
        graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
        enable_security_testing=True,
    )
    engine._attacker = MagicMock()
    engine._auditor = MagicMock()
    engine._run_3agent_pipeline = MagicMock()
    engine._run_local_mutator_security_case = MagicMock()
    engine._capture_valid_workflow(
        {"id": "getOrder", "method": "GET", "path": "/orders/{orderId}"},
        StateStore({"actor_id": "owner-a", "orderId": "old-order"}),
        {
            "status": 200,
            "successful": True,
            "sent_payload": {"orderId": "old-order"},
            "raw_response": {"id": "old-order"},
        },
        ["getOrder"],
    )

    summary = engine.run_security_phase()

    assert summary["baseline_replay_failures"] == 1
    assert summary["tested_endpoints"] == 0
    engine._run_local_mutator_security_case.assert_not_called()
    engine._run_3agent_pipeline.assert_not_called()


def test_optional_post_reference_is_resolved_and_exact_provider_is_preferred():
    executor = MagicMock()
    state = StateStore({"actor_id": "actor-a"})

    def execute_request(*, api_node, current_state, edge_deps):
        if api_node["id"] == "createArtifact":
            current_state.update("artifactId", 42)
        return {
            "status": 201,
            "successful": True,
            "response_text": '{"id": 42}',
            "sent_payload": {},
            "raw_response": {"id": 42},
        }

    executor.execute_request.side_effect = execute_request
    operations = [
        {
            "id": "listArtifacts",
            "method": "GET",
            "path": "/artifacts",
            "outputs": {"artifactList": {"type": "array"}},
        },
        {
            "id": "createArtifact",
            "method": "POST",
            "path": "/artifacts",
            "outputs": {"artifactid": {"original": "artifactId", "type": "integer"}},
        },
        {
            "id": "attachArtifact",
            "method": "POST",
            "path": "/containers/artifacts",
            "inputs": {
                "artifactid": {
                    "original": "artifactId",
                    "in": "body",
                    "type": "integer",
                    "required": False,
                }
            },
        },
    ]
    adjacency = {
        "listArtifacts": [{
            "to": "attachArtifact",
            "dependencies": [{
                "producer_field": "artifactList",
                "consumer_field": "artifactId",
                "confidence": 0.85,
            }],
        }],
        "createArtifact": [{
            "to": "attachArtifact",
            "dependencies": [{
                "producer_field": "artifactId",
                "consumer_field": "artifactId",
                "confidence": 0.52,
            }],
        }],
    }
    engine = TestStrategyEngine(
        operations=operations,
        adjacency_list=adjacency,
        request_executor=executor,
        graph_builder=MagicMock(),
        knowledge_memory=KnowledgeMemory(),
    )

    chain = ["attachArtifact"]
    engine.resolve_missing_dependencies(operations[-1], state, chain)

    assert state.get("artifactId") == 42
    assert chain == ["createArtifact", "attachArtifact"]
    assert executor.execute_request.call_count == 1
    assert executor.execute_request.call_args.kwargs["api_node"]["id"] == "createArtifact"
