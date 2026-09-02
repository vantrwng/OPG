from unittest.mock import MagicMock

from attack_store import AttackStore
from auditor_agent import AuditorAgent
from state_store import ActorContext, MultiActorContextStore, StateStore
from knowledge_memory import KnowledgeMemory
from test_strategy_engine import TestStrategyEngine


def test_multi_actor_contexts_keep_credentials_isolated():
    actors = MultiActorContextStore()
    actors.add(ActorContext("owner-a", auth_token="token-a", credentials={"email": "a@test"}))
    actors.add(ActorContext("user-b", auth_token="token-b", credentials={"email": "b@test"}))

    state_a = actors.require("owner-a").to_state_store()
    state_b = actors.require("user-b").to_state_store()

    assert state_a.get("auth_token") == "token-a"
    assert state_b.get("auth_token") == "token-b"
    assert state_a.get("email") != state_b.get("email")


def test_attack_store_returns_only_resources_with_foreign_provenance():
    store = AttackStore()
    store.record(
        "getOrder", "orderId", "order-a", user_context={"actor_id": "owner-a"},
        owner_actor_id="owner-a", confidence=0.9,
    )
    store.record(
        "getOrder", "orderId", "order-b", user_context={"actor_id": "user-b"},
        owner_actor_id="user-b", confidence=0.9,
    )

    foreign = store.get_foreign_ids("getOrder", {"actor_id": "owner-a"})

    assert [entry["resource_id"] for entry in foreign] == ["order-b"]


def test_deterministic_oracle_confirms_explicit_foreign_owner():
    llm = MagicMock()
    auditor = AuditorAgent(client=llm)
    state = StateStore({"actor_id": "owner-a", "user_id": "1"})

    result = auditor.audit(
        {
            "strategy": "reference_forge",
            "extra": {
                "owner_actor_id": "owner-a", "attacker_actor_id": "user-b",
                "owner_role": "USER", "attacker_role": "USER",
                "provenance": "CREATED_RESPONSE", "confirmation_eligible": True,
                "preflight_ok": True, "operation": "GET",
                "reproduction_count": 2, "fingerprint_verified": True,
            },
        },
        {"status": 200, "raw_response": {"id": "order-2", "owner_id": "2"}},
        {"status": 200, "raw_response": {"id": "order-1", "owner_id": "1"}},
        StateStore({"actor_id": "user-b", "user_id": "1"}),
        {"id": "getOrder", "method": "GET", "path": "/orders/{id}"},
    )

    assert result.is_bola is True
    assert result.classification == "CONFIRMED"
    assert result.bola_type == "BOLA"
    llm.auditor.assert_not_called()


def test_deterministic_oracle_never_confirms_unknown_roles():
    auditor = AuditorAgent(client=MagicMock())
    result = auditor.audit(
        {
            "strategy": "reference_forge",
            "extra": {
                "owner_actor_id": "owner-a", "attacker_actor_id": "user-b",
                "owner_role": "unknown", "attacker_role": "unknown",
                "provenance": "CREATED_RESPONSE", "confirmation_eligible": True,
                "preflight_ok": True, "operation": "GET",
                "reproduction_count": 2, "fingerprint_verified": True,
            },
        },
        {"status": 200, "raw_response": {"id": "memo-2"}},
        {"status": 200, "raw_response": {"id": "memo-1"}},
        StateStore({"actor_id": "user-b"}),
        {"id": "getMemo", "method": "GET", "path": "/memo/{id}"},
    )

    assert result.classification != "CONFIRMED"
    assert result.is_bola is False


def test_deterministic_oracle_rejects_authorization_denial():
    auditor = AuditorAgent(client=MagicMock())
    result = auditor.audit(
        {"strategy": "reference_forge", "extra": {
            "confirmation_eligible": True, "provenance": "CREATED_RESPONSE",
            "preflight_ok": True,
        }},
        {"status": 403, "raw_response": {"error": "forbidden"}},
        None,
        StateStore({"actor_id": "owner-a", "user_id": "1"}),
        {"method": "GET", "path": "/orders/{id}"},
    )

    assert result.is_bola is False
    assert result.classification == "REJECTED"


def test_post_resource_is_reused_by_consumer_selector_alias():
    store = AttackStore()
    store.record(
        "createMemo", "id", "memo-7", owner_actor_id="owner-a",
        owner_role="USER", resource_type="/memo", provenance="CREATED_RESPONSE",
    )

    resources = store.get_foreign_resources(
        resource_type="/memo/{memoId}", selector_field="memoId",
        attacker_actor_id="user-b", attacker_role="USER",
    )

    assert [entry["resource_id"] for entry in resources] == ["memo-7"]


def test_deleted_resource_is_removed_from_attack_store():
    store = AttackStore()
    store.record(
        "createResource", "id", 3, owner_actor_id="owner-a",
        resource_type="/resource", provenance="CREATED_RESPONSE",
    )
    removed = store.invalidate(
        "/resource/{resourceId}", "resourceId", 3, owner_actor_id="owner-a"
    )
    assert removed == 1
    assert store.get_all_ids_for_api("/resource") == []


def test_guessed_identifier_can_never_confirm_bola():
    auditor = AuditorAgent(client=MagicMock())
    result = auditor.audit(
        {"strategy": "reference_forge", "extra": {
            "provenance": "GUESSED", "confirmation_eligible": False,
        }},
        {"status": 200, "raw_response": {"id": "guessed"}}, None,
        StateStore({"actor_id": "user-b"}),
        {"method": "GET", "path": "/memo/{memoId}"},
    )
    assert result.classification == "NOT_TESTED"
    assert result.is_bola is False


def test_html_200_is_not_api_success_for_oracle():
    auditor = AuditorAgent(client=MagicMock())
    result = auditor.audit(
        {"strategy": "reference_forge", "extra": {
            "provenance": "CREATED_RESPONSE", "confirmation_eligible": True,
            "preflight_ok": True,
        }},
        {"status": 200, "response_content_type": "text/html",
         "response_text": "<!doctype html><html></html>"}, None,
        StateStore({"actor_id": "user-b"}),
        {"method": "GET", "path": "/memo/{memoId}", "outputs": {"id": {}}},
    )
    assert result.classification == "INCONCLUSIVE"


def test_only_one_successful_reproduction_is_inconclusive():
    auditor = AuditorAgent(client=MagicMock())
    result = auditor.audit(
        {"strategy": "reference_forge", "extra": {
            "owner_actor_id": "owner-a", "attacker_actor_id": "user-b",
            "owner_role": "USER", "attacker_role": "USER",
            "provenance": "CREATED_RESPONSE", "confirmation_eligible": True,
            "preflight_ok": True, "operation": "GET",
            "reproduction_count": 1, "fingerprint_verified": True,
        }},
        {"status": 200, "raw_response": {"id": "memo-7"}},
        {"status": 200, "raw_response": {"id": "memo-7"}},
        StateStore({"actor_id": "user-b"}),
        {"method": "GET", "path": "/memo/{memoId}"},
    )
    assert result.classification == "INCONCLUSIVE"
    assert result.is_bola is False


def test_patch_requires_owner_readback_and_two_reproductions():
    auditor = AuditorAgent(client=MagicMock())
    common = {
        "owner_actor_id": "owner-a", "attacker_actor_id": "user-b",
        "owner_role": "USER", "attacker_role": "USER",
        "provenance": "CREATED_RESPONSE", "confirmation_eligible": True,
        "preflight_ok": True, "operation": "PATCH", "reproduction_count": 2,
    }
    vulnerable = auditor.audit(
        {"strategy": "reference_forge", "extra": {**common, "mutation_verified": True}},
        {"status": 200, "raw_response": {"id": "memo-7"}},
        {"status": 200, "raw_response": {"id": "memo-7"}},
        StateStore({"actor_id": "user-b"}),
        {"method": "PATCH", "path": "/memo/{memoId}"},
    )
    secure = auditor.audit(
        {"strategy": "reference_forge", "extra": {**common, "mutation_verified": False}},
        {"status": 200, "raw_response": {"id": "memo-7"}},
        {"status": 200, "raw_response": {"id": "memo-7"}},
        StateStore({"actor_id": "user-b"}),
        {"method": "PATCH", "path": "/memo/{memoId}"},
    )
    assert vulnerable.classification == "CONFIRMED"
    assert secure.classification == "INCONCLUSIVE"


def test_bootstrapped_user_ids_become_created_same_role_resources():
    engine = TestStrategyEngine(
        operations=[], adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )
    actors = MultiActorContextStore()
    actors.add(ActorContext(
        "owner-a", role="USER", credentials={"user_id": 11}
    ))
    actors.add(ActorContext(
        "user-b", role="USER", credentials={"user_id": 12}
    ))
    engine.actor_contexts = actors

    assert engine.seed_actor_identity_resources("signup") == 2
    foreign = engine.attack_store.get_foreign_resources(
        "user", "id", attacker_actor_id="user-b", attacker_role="USER"
    )
    assert any(item["resource_id"] == "11" for item in foreign)
    assert all(item["provenance"] == "CREATED_RESPONSE" for item in foreign)


def _same_role_pipeline_engine():
    operation = {
        "id": "GET__memo_{memoId}",
        "method": "GET",
        "path": "/memo/{memoId}",
    }
    memory = KnowledgeMemory()
    engine = TestStrategyEngine(
        operations=[operation], adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=memory,
    )
    actors = MultiActorContextStore()
    actors.add(ActorContext("owner-a", role="USER", auth_token="token-a"))
    actors.add(ActorContext("user-b", role="USER", auth_token="token-b"))
    engine.actor_contexts = actors
    engine._attacker = MagicMock()
    engine._auditor = MagicMock()
    engine._preflight_actor = MagicMock(return_value=(True, "verified"))
    return engine, memory, operation


def test_three_agent_pipeline_passes_baseline_response_to_attacker():
    engine, memory, operation = _same_role_pipeline_engine()
    engine._attacker.generate_attacks.return_value = []
    owner_state = StateStore({
        "actor_id": "owner-a", "actor_role": "USER", "auth_token": "token-a",
    })
    baseline_body = {"data": {"id": 41, "creatorId": 2}}

    engine._run_3agent_pipeline(
        api_node=operation,
        current_state=owner_state,
        exec_result={
            "status": 200,
            "successful": True,
            "sent_payload": {},
            "raw_response": baseline_body,
        },
        beam_chain=[operation["id"]],
        vulnerabilities=[],
    )

    engine._attacker.generate_attacks.assert_called_once()
    assert engine._attacker.generate_attacks.call_args.kwargs["valid_response"] \
        == baseline_body
    assert memory.security_observations == []


def test_attack_generation_failure_is_reported_as_infrastructure_failure():
    engine, memory, operation = _same_role_pipeline_engine()
    engine._attacker.generate_attacks.side_effect = RuntimeError("generator stopped")

    engine._run_3agent_pipeline(
        api_node=operation,
        current_state=StateStore({
            "actor_id": "owner-a", "actor_role": "USER", "auth_token": "token-a",
        }),
        exec_result={
            "status": 200,
            "successful": True,
            "sent_payload": {},
            "raw_response": {"data": {"id": 41}},
        },
        beam_chain=[operation["id"]],
        vulnerabilities=[],
    )

    assert memory.security_observations == [{
        "classification": "INFRA_FAILURE",
        "type": "BOLA",
        "api": operation["id"],
        "owner_actor_id": "owner-a",
        "attacker_actor_id": "user-b",
        "reasoning": "Attack generation failed: RuntimeError: generator stopped",
    }]
