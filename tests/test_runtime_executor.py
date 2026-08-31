from unittest.mock import MagicMock

from runtime_executor import RequestExecutor
from state_store import StateStore


def _response(status=200, body=None):
    response = MagicMock()
    response.status_code = status
    response.text = "{}" if body is None else __import__("json").dumps(body)
    response.json.return_value = {} if body is None else body
    return response


def test_prepare_request_preserves_openapi_parameter_locations():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    node = {
        "id": "updateOrder",
        "method": "PATCH",
        "path": "/orders/{orderId}",
        "inputs": {
            "order_id": {"original": "orderId", "in": "path"},
            "include": {"original": "include", "in": "query"},
            "trace": {"original": "X-Trace", "in": "header"},
            "name": {"original": "name", "in": "body"},
        },
    }
    prepared = executor.prepare_request(
        node,
        StateStore({"auth_token": "abc", "auth_header_prefix": "Bearer"}),
        {"orderId": 42, "include": "owner", "X-Trace": "t-1", "name": "changed"},
        "TEST",
    )

    assert prepared.url == "https://target.test/orders/42"
    assert prepared.query_params == {"include": "owner"}
    assert prepared.headers["X-Trace"] == "t-1"
    assert prepared.headers["Authorization"] == "Bearer abc"
    assert prepared.json_body == {"name": "changed"}


def test_get_query_inputs_are_sent_as_params():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"ownerId": "user-b"}, "HEURISTIC")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(200, {"items": []}))

    result = executor.execute_request(
        {
            "id": "listOrders",
            "method": "GET",
            "path": "/orders",
            "inputs": {"ownerId": {"in": "query", "original": "ownerId"}},
        },
        StateStore(),
    )

    kwargs = executor._session.request.call_args.kwargs
    assert kwargs["params"] == {"ownerId": "user-b"}
    assert result["sent_query"] == {"ownerId": "user-b"}


def test_payload_override_is_the_payload_sent_by_attack():
    planner = MagicMock()
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(200, {"owner_id": "user-b"}))
    attack_payload = {"ownerId": "user-b", "role": "admin"}

    result = executor.execute_request(
        {"id": "patchUser", "method": "PATCH", "path": "/users", "inputs": {}},
        StateStore({"actor_id": "user-a"}),
        payload_override=attack_payload,
        payload_source_override="ATTACKER_REFERENCE_FORGE",
        allow_repair=False,
    )

    planner.generate_payload.assert_not_called()
    assert executor._session.request.call_args.kwargs["json"] == attack_payload
    assert result["sent_payload"] == attack_payload
    assert result["actor_id"] == "user-a"


def test_authorization_denial_is_not_self_healed():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"ownerId": "user-b"}, "HEURISTIC")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(403, {"error": "forbidden"}))

    executor.execute_request(
        {"id": "patchUser", "method": "PATCH", "path": "/users", "inputs": {}},
        StateStore(),
    )

    planner.repair_payload.assert_not_called()
