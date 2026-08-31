from unittest.mock import MagicMock

from attack_store import AttackStore
from auditor_agent import AuditorAgent
from state_store import ActorContext, MultiActorContextStore, StateStore


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
            "extra": {"owner_actor_id": "owner-a", "attacker_actor_id": "user-b"},
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


def test_deterministic_oracle_rejects_authorization_denial():
    auditor = AuditorAgent(client=MagicMock())
    result = auditor.audit(
        {"strategy": "reference_forge"},
        {"status": 403, "raw_response": {"error": "forbidden"}},
        None,
        StateStore({"actor_id": "owner-a", "user_id": "1"}),
        {"method": "GET", "path": "/orders/{id}"},
    )

    assert result.is_bola is False
    assert result.classification == "REJECTED"
