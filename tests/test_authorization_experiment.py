import json
from pathlib import Path

from attack_store import AttackStore
from auditor_agent import AuditorAgent
from authorization_experiment import AuthorizationExperimentPlanner
from attacker_agent import AttackVariant, AttackerAgent
from knowledge_memory import KnowledgeMemory
from spec_parser import SpecParser
from state_store import ActorContext, MultiActorContextStore, StateStore
from test_strategy_engine import TestStrategyEngine
from reference_engine import ObservedValue, ProvenanceChain, ProvenanceLevel
from unittest.mock import MagicMock


def _crud_operations():
    return [
        {
            "id": "createMemo", "method": "POST", "path": "/memo",
            "outputs": {"memoid": {
                "original": "memoId", "json_path": "data.memoId",
                "type": "integer",
            }},
        },
        {"id": "getMemo", "method": "GET", "path": "/memo/{memoId}"},
        {"id": "patchMemo", "method": "PATCH", "path": "/memo/{memoId}"},
        {"id": "deleteMemo", "method": "DELETE", "path": "/memo/{memoId}"},
    ]


def test_id_substitution_uses_canonical_identity_metadata_without_treating_own_id_as_foreign():
    attacker = AttackerAgent(max_variants=3)
    attacker.reference_discovery.pool.observe(ObservedValue(
        value="user-b",
        schema={"type": "string"},
        location="path",
        field_path="username",
        provenance=ProvenanceChain.single(
            "actor_bootstrap", ProvenanceLevel.AUTHORITATIVE,
            actor_id="user-b", operation_id="registerUser",
            relation="user",
        ),
        operation_id="registerUser",
        actor_id="user-b",
        relationship="user",
    ))
    operation = {
        "id": "getUser", "method": "GET", "path": "/users/{username}",
        "resource_type": "user",
        "inputs": {"username": {
            "original": "username", "in": "path", "type": "string",
        }},
    }

    variants = attacker._id_substitution(
        operation, StateStore({"actor_id": "user-b"}), {"username": "owner-a"}
    )

    assert len(variants) == 1
    assert variants[0].extra["resource_id"] == "user-b"
    assert variants[0].extra["selector_field"] == "username"
    assert variants[0].extra["resource_type"] == "user"
    assert variants[0].extra["confirmation_eligible"] is False


def test_read_only_parameter_pollution_never_generates_body_mass_assignment():
    attacker = AttackerAgent(max_variants=4)
    variants = attacker._parameter_pollution(
        {"id": "getUser", "method": "GET", "path": "/users/{username}"},
        StateStore({"actor_id": "user-b"}),
        {"username": "owner-a"},
    )

    assert variants
    assert {item.extra["technique"] for item in variants} == {"query_pollution"}


def test_planner_builds_schema_backed_patch_and_delete_experiments():
    planner = AuthorizationExperimentPlanner(_crud_operations())
    experiments = {item.target_api: item for item in planner.plan()}

    assert experiments["patchMemo"].producer_api == "createMemo"
    assert experiments["patchMemo"].verifier_api == "getMemo"
    assert experiments["deleteMemo"].operation == "DELETE"
    assert planner.validate(experiments["deleteMemo"])


def test_planner_does_not_invent_missing_producer_or_verifier():
    planner = AuthorizationExperimentPlanner([
        {"id": "deleteWidget", "method": "DELETE", "path": "/widget/{widgetKey}"},
    ])
    assert planner.plan() == []


def test_planner_is_selector_name_agnostic():
    planner = AuthorizationExperimentPlanner([
        {"id": "createBook", "method": "POST", "path": "/books"},
        {"id": "readBook", "method": "GET", "path": "/books/{isbn}"},
        {"id": "removeBook", "method": "DELETE", "path": "/books/{isbn}"},
    ])
    experiment = planner.for_target("removeBook")
    assert experiment is not None
    assert experiment.selector_field == "isbn"
    assert experiment.resource_type == "book"


def test_planner_prefers_direct_collection_producer_over_relationship_post():
    operations = [
        {"id": "attachResource", "method": "POST",
         "path": "/memo/{memoId}/resource"},
        {"id": "createResource", "method": "POST", "path": "/resource"},
        {"id": "readResource", "method": "GET",
         "path": "/resource/{resourceId}"},
    ]

    experiment = AuthorizationExperimentPlanner(operations).for_target("readResource")

    assert experiment is not None
    assert experiment.producer_api == "createResource"


def test_planner_treats_password_action_as_user_resource_family():
    operations = [
        {"id": "registerUser", "method": "POST", "path": "/users/v1/register"},
        {"id": "loginUser", "method": "POST", "path": "/users/v1/login"},
        {"id": "getUser", "method": "GET", "path": "/users/v1/{username}"},
        {"id": "updatePassword", "method": "PUT",
         "path": "/users/v1/{username}/password"},
    ]

    experiment = AuthorizationExperimentPlanner(operations).for_target("updatePassword")

    assert experiment is not None
    assert experiment.resource_type == "user"
    assert experiment.producer_api == "registerUser"
    assert experiment.verifier_api == "getUser"


def test_nested_sensitive_response_fields_are_extracted_from_arrays():
    spec_path = Path(__file__).resolve().parents[1] / "vmAPI.json"
    operation = next(
        op for op in SpecParser(str(spec_path)).extract_operations()
        if op["path"] == "/users/v1/_debug"
    )

    assert set(operation["sensitive_response_fields"]) >= {"admin", "email", "password"}


def test_successful_create_request_postcondition_is_authoritative_resource():
    spec_path = Path(__file__).resolve().parents[1] / "vmAPI.json"
    operations = SpecParser(str(spec_path)).extract_operations()
    create_book = next(op for op in operations if op["path"] == "/books/v1" and op["method"] == "POST")
    engine = TestStrategyEngine(
        operations=operations, adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )

    recorded = engine._record_response_resources(
        create_book,
        StateStore({"actor_id": "owner-a", "actor_role": "USER"}),
        {
            "status": 200, "successful": True, "schema_valid": True,
            "sent_payload": {"book_title": "Foreign Book", "secret": "x"},
            "raw_response": {"status": "success", "message": "created"},
        },
    )
    resources = engine.attack_store.get_foreign_resources(
        "book", "book_title", "user-b", "USER"
    )

    assert recorded == 1
    assert resources[0]["resource_id"] == "Foreign Book"
    assert resources[0]["provenance"] == "CREATED_REQUEST"


def test_ref_component_name_is_not_inserted_into_wire_json_path(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/memo": {
                "post": {
                    "responses": {"200": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/MemoEnvelope"}
                    }}}}
                }
            },
            "/memo/{memoId}": {
                "get": {
                    "parameters": [{
                        "name": "memoId", "in": "path", "required": True,
                        "schema": {"type": "integer"},
                    }],
                    "responses": {"200": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/MemoEnvelope"}
                    }}}},
                }
            },
        },
        "components": {"schemas": {
            "MemoEnvelope": {"type": "object", "properties": {
                "data": {"$ref": "#/components/schemas/Memo"},
            }},
            "Memo": {"type": "object", "properties": {
                "id": {"type": "integer"},
            }},
        }},
    }
    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    parser = SpecParser(str(spec_path))
    parser.extract_operations()
    producer = next(op for op in parser.operations if op["method"] == "POST")
    selector_meta = producer["outputs"]["memoid"]

    assert selector_meta["json_path"] == "data.id"

    engine = TestStrategyEngine(
        operations=parser.operations, adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )
    recorded = engine._record_response_resources(
        producer, StateStore({"actor_id": "user_b", "actor_role": "USER"}),
        {"successful": True, "schema_valid": True,
         "raw_response": {"data": {"id": 42}}},
    )

    assert recorded == 1
    assert engine.attack_store.total_entries == 1


def test_memos_created_ids_feed_collection_and_item_reference_forge():
    spec_path = Path(__file__).resolve().parents[1] / "memo_openapi.json"
    parser = SpecParser(str(spec_path))
    parser.extract_operations()
    operations = {operation["id"]: operation for operation in parser.operations}
    engine = TestStrategyEngine(
        operations=parser.operations, adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )
    created = {
        "POST__memo": ("memo", 41, 42),
        "POST__shortcut": ("shortcut", 10, 11),
        "POST__resource": ("resource", 30, 31),
    }
    for producer_api, (_resource_type, owner_id, attacker_id) in created.items():
        for actor_id, resource_id in (("user_b", owner_id), ("user_c", attacker_id)):
            count = engine._record_response_resources(
                operations[producer_api],
                StateStore({"actor_id": actor_id, "actor_role": "USER"}),
                {"successful": True, "schema_valid": True,
                 "raw_response": {"data": {"id": resource_id}}},
            )
            assert count >= 1

    attacker = AttackerAgent(attack_store=engine.attack_store)
    attacker_state = StateStore({"actor_id": "user_c", "actor_role": "USER"})
    expected_paths = {
        "GET__memo": "/memo",
        "GET__memo_{memoId}": "/memo/41",
        "GET__shortcut": "/shortcut",
        "GET__shortcut_{shortcutId}": "/shortcut/10",
        "GET__resource": "/resource",
        "GET__resource_{resourceId}": "/resource/30",
    }
    for api_id, expected_path in expected_paths.items():
        variants = attacker._reference_forge(
            operations[api_id], attacker_state, payload={}
        )
        eligible = [
            variant for variant in variants
            if variant.extra.get("confirmation_eligible")
            and variant.extra.get("owner_actor_id") == "user_b"
        ]
        assert eligible
        assert eligible[0].path == expected_path


def test_reference_forge_uses_leaf_selector_for_nested_resource():
    store = AttackStore()
    store.record(
        "POST__resource", "resourceId", 30,
        owner_actor_id="user_b", owner_role="USER",
        resource_type="resource", provenance="CREATED_RESPONSE",
    )
    attacker = AttackerAgent(attack_store=store)
    operation = {
        "id": "DELETE__memo_{memoId}_resource_{resourceId}",
        "method": "DELETE",
        "path": "/memo/{memoId}/resource/{resourceId}",
        "resource_selectors": ["memoId", "resourceId"],
    }

    variants = attacker._reference_forge(
        operation,
        StateStore({"actor_id": "user_c", "actor_role": "USER"}),
        payload={},
    )

    eligible = [
        variant for variant in variants
        if variant.extra.get("confirmation_eligible")
    ]
    assert len(eligible) == 1
    assert eligible[0].extra["field"] == "resourceId"
    assert eligible[0].extra["selector_field"] == "id"
    assert eligible[0].path == "/memo/{memoId}/resource/30"


def test_pipeline_confirms_cross_actor_patch_from_pre_and_post_owner_reads():
    operations = _crud_operations()
    executor = MagicMock()
    memory = KnowledgeMemory()
    engine = TestStrategyEngine(
        operations=operations, adjacency_list={}, request_executor=executor,
        graph_builder=MagicMock(), knowledge_memory=memory,
    )
    actors = MultiActorContextStore()
    actors.add(ActorContext("owner-a", role="USER", auth_token="token-a"))
    actors.add(ActorContext("user-b", role="USER", auth_token="token-b"))
    engine.actor_contexts = actors
    engine._preflight_actor = MagicMock(return_value=(True, "verified"))
    engine._attacker = AttackerAgent(attack_store=engine.attack_store)
    engine._attacker._id_substitution = MagicMock(return_value=[])
    engine._attacker._parameter_pollution = MagicMock(return_value=[])
    engine._auditor = AuditorAgent(client=MagicMock())
    engine.attack_store.record(
        "createMemo", "memoId", 41,
        owner_actor_id="owner-a", owner_role="USER",
        resource_type="memo", provenance="CREATED_RESPONSE",
    )

    executor.execute_request.side_effect = [
        {"status": 200, "successful": True, "schema_valid": True,
         "raw_response": {"memoId": 41, "title": "before"}},
        {"status": 200, "successful": True, "schema_valid": True,
         "raw_response": {"memoId": 41, "title": "updated"},
         "response_text": '{"memoId":41,"title":"updated"}',
         "url": "/memo/41", "sent_payload": {"title": "updated"}},
        {"status": 200, "successful": True, "schema_valid": True,
         "raw_response": {"memoId": 41, "title": "updated"}},
        {"status": 201, "successful": True, "schema_valid": True,
         "raw_response": {"data": {"memoId": 42, "title": "fresh"}}},
        {"status": 200, "successful": True, "schema_valid": True,
         "raw_response": {"memoId": 42, "title": "updated"}},
        {"status": 200, "successful": True, "schema_valid": True,
         "raw_response": {"memoId": 42, "title": "updated"}},
    ]
    owner_state = StateStore({
        "actor_id": "owner-a", "actor_role": "USER", "auth_token": "token-a",
        "memoId": 7,
    })
    patch_operation = next(op for op in operations if op["id"] == "patchMemo")

    engine._run_3agent_pipeline(
        api_node=patch_operation,
        current_state=owner_state,
        exec_result={
            "status": 200, "successful": True, "schema_valid": True,
            "sent_payload": {"title": "updated"},
            "raw_response": {"memoId": 7, "title": "updated"},
        },
        beam_chain=["patchMemo"],
        vulnerabilities=[],
    )

    assert any(finding.get("type") == "BOLA" for finding in memory.findings)
    sources = [
        call.kwargs.get("payload_source_override")
        for call in executor.execute_request.call_args_list
    ]
    assert sources == [
        "BOLA_OWNER_PRECHECK",
        "ATTACKER_REFERENCE_FORGE",
        "BOLA_OWNER_VERIFY",
        "RESOURCE_PROVISIONER",
        "DETERMINISTIC_BOLA_REPLAY",
        "BOLA_OWNER_VERIFY",
    ]


def _delete_engine(responses):
    executor = MagicMock()
    executor.execute_request.side_effect = responses
    engine = TestStrategyEngine(
        operations=_crud_operations(), adjacency_list={}, request_executor=executor,
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )
    variant = AttackVariant(
        strategy="reference_forge",
        api_node=_crud_operations()[-1], payload={}, path="/memo/1",
        description="foreign memo",
        extra={"resource_id": 1, "resource_type": "memo", "selector_field": "memoId"},
    )
    return engine, variant


def test_delete_reproduction_confirms_real_owner_side_effect_on_fresh_resource():
    engine, variant = _delete_engine([
        {"status": 201, "successful": True, "schema_valid": True,
         "raw_response": {"data": {"memoId": 22}}},
        {"status": 200, "successful": True, "schema_valid": True},
        {"status": 404, "successful": False, "schema_valid": True},
    ])
    assert engine._reproduce_mutation_with_fresh_resource(
        _crud_operations()[-1], variant,
        StateStore({"actor_id": "a", "actor_role": "USER"}),
        StateStore({"actor_id": "b", "actor_role": "USER"}), "DELETE",
    ) is True


def test_delete_reproduction_rejects_secure_authorization_case():
    engine, variant = _delete_engine([
        {"status": 201, "successful": True, "schema_valid": True,
         "raw_response": {"data": {"memoId": 23}}},
        {"status": 403, "successful": False, "schema_valid": True},
    ])
    assert engine._reproduce_mutation_with_fresh_resource(
        _crud_operations()[-1], variant,
        StateStore({"actor_id": "a", "actor_role": "USER"}),
        StateStore({"actor_id": "b", "actor_role": "USER"}), "DELETE",
    ) is False


def test_fingerprint_uses_exact_structured_selector_value():
    base = {"status": 200, "successful": True, "schema_valid": True}

    assert TestStrategyEngine._response_has_fingerprint(
        {**base, "raw_response": {"memoId": "1"}},
        "1", selector_field="memoId", resource_type="memo",
    ) is True
    assert TestStrategyEngine._response_has_fingerprint(
        {**base, "raw_response": {"memoId": "10", "createdAt": 1710000001}},
        "1", selector_field="memoId", resource_type="memo",
    ) is False


def test_post_does_not_harvest_unrelated_nested_id_as_created_resource():
    operations = _crud_operations()
    engine = TestStrategyEngine(
        operations=operations, adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )

    count = engine._record_response_resources(
        operations[0], StateStore({"actor_id": "a", "actor_role": "USER"}),
        {
            "status": 201, "successful": True, "schema_valid": True,
            "raw_response": {"audit": {"id": 99}},
        },
    )

    assert count == 0
    assert engine.attack_store.total_entries == 0


def test_patch_selector_alone_is_not_mutation_evidence():
    assert TestStrategyEngine._mutation_matches(
        {"memoId": 7}, {"memoId": 7}, "memoId", "memo",
        {"memoId": 7},
    ) is False


def test_attack_store_is_isolated_per_engine_run():
    kwargs = {
        "operations": _crud_operations(), "adjacency_list": {},
        "request_executor": MagicMock(), "graph_builder": MagicMock(),
        "knowledge_memory": KnowledgeMemory(),
    }
    first = TestStrategyEngine(**kwargs)
    second = TestStrategyEngine(**kwargs)
    first.attack_store.record(
        "createMemo", "memoId", 7, owner_actor_id="a", owner_role="USER",
        resource_type="memo", provenance="CREATED_RESPONSE",
    )

    assert first.attack_store.total_entries == 1
    assert second.attack_store.total_entries == 0


def test_captured_workflow_keeps_its_own_endpoint_baseline():
    operation = {"id": "getMemo", "method": "GET", "path": "/memo/{memoId}"}
    engine = TestStrategyEngine(
        operations=[operation], adjacency_list={}, request_executor=MagicMock(),
        graph_builder=MagicMock(), knowledge_memory=KnowledgeMemory(),
    )
    response = {"status": 200, "successful": True, "raw_response": {"id": 7}}

    engine._capture_valid_workflow(
        operation, StateStore({"actor_id": "user_b", "actor_role": "USER"}),
        response, ["getMemo"],
    )

    case = engine._valid_workflows[("user_b", "getMemo")]
    assert case["state"].get_baseline("getMemo") == response
