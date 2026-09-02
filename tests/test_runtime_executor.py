from unittest.mock import MagicMock
from requests.cookies import RequestsCookieJar

from runtime_executor import RequestExecutor
from state_store import StateStore


def _response(status=200, body=None):
    response = MagicMock()
    response.status_code = status
    response.headers = {}
    response.cookies = RequestsCookieJar()
    if body is None:
        response.text = ""
        response.json.side_effect = ValueError("empty response body")
    else:
        response.text = __import__("json").dumps(body)
        response.json.return_value = body
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


def test_binary_200_matching_openapi_media_type_is_successful():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"resourceId": 7}, "STATE_BINDING")
    executor = RequestExecutor("https://target.test", planner=planner)
    response = MagicMock()
    response.status_code = 200
    response.text = "OPG_BINARY_FIXTURE"
    response.headers = {"Content-Type": "application/octet-stream"}
    response.cookies.get_dict.return_value = {}
    response.json.side_effect = ValueError("binary response")
    executor._session.request = MagicMock(return_value=response)

    result = executor.execute_request({
        "id": "GET__resource_{resourceId}_blob", "method": "GET",
        "path": "/resource/{resourceId}/blob",
        "inputs": {"resourceid": {
            "original": "resourceId", "type": "integer", "required": True, "in": "path",
        }},
        "outputs": {"resourceid": {"original": "resourceId", "_passthrough": True}},
        "response_content_types": ["application/octet-stream"],
        "expected_success_statuses": ["200"],
    }, StateStore({"resourceId": 7}), allow_repair=False)

    assert result["status"] == 200
    assert result["successful"] is True
    assert result["semantic_failure"] is False
    assert result["schema_valid"] is True


def test_declared_json_body_must_parse_even_without_flattened_outputs():
    valid, errors = RequestExecutor._validate_response_contract(
        response_json=None,
        response_text="not-json",
        content_type="application/json",
        outputs={},
        status=200,
        expected_content_types=["application/json"],
        response_body_statuses=["200"],
    )

    assert valid is False
    assert errors == ["OpenAPI declares a response body but JSON parsing failed"]


def test_successful_delete_tombstones_terminal_path_resource():
    planner = MagicMock()
    planner.generate_payload.return_value = (
        {"memoId": 10, "resourceId": 3}, "HEURISTIC"
    )
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(204, None))
    state = StateStore({"memoId": 10, "resourceId": 3})
    result = executor.execute_request({
        "id": "DELETE__memo_{memoId}_resource_{resourceId}",
        "method": "DELETE", "path": "/memo/{memoId}/resource/{resourceId}",
        "expected_success_statuses": ["204"],
        "inputs": {
            "memoid": {"original": "memoId", "in": "path", "type": "integer"},
            "resourceid": {"original": "resourceId", "in": "path", "type": "integer"},
        },
    }, state)

    assert result["successful"] is True
    assert state.get("memoId") == 10
    assert state.get("resourceId") is None
    assert state.is_deleted_reference("resource_id", 3)
    assert result["deleted_references"][0]["resource_id"] == "3"


def test_204_without_declared_body_accepts_passthrough_outputs():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"resourceId": 7}, "STATE_BINDING")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(204))

    result = executor.execute_request({
        "id": "archiveResource",
        "method": "DELETE",
        "path": "/resources/{resourceId}",
        "inputs": {"resourceid": {
            "original": "resourceId", "in": "path", "type": "integer",
        }},
        "outputs": {"resourceid": {
            "original": "resourceId", "_passthrough": True,
        }},
        "expected_success_statuses": ["204"],
        "response_content_types": [],
        "response_body_statuses": [],
    }, StateStore({"resourceId": 7}), allow_repair=False)

    assert result["successful"] is True
    assert result["schema_valid"] is True


def test_transport_follows_same_origin_redirect_and_preserves_auth():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    redirect = _response(307)
    redirect.headers = {"Location": "/v2/resources"}
    executor._session.request = MagicMock(side_effect=[redirect, _response(200, {})])
    prepared = executor.prepare_request(
        {"id": "resource", "method": "GET", "path": "/v1/resources"},
        StateStore({"auth_token": "secret", "auth_header_prefix": "Bearer"}),
        {}, "TEST",
    )

    response = executor._fire_prepared_request(prepared)

    assert response.status_code == 200
    assert executor._session.request.call_count == 2
    followup = executor._session.request.call_args.kwargs
    assert followup["url"] == "https://target.test/v2/resources"
    assert followup["headers"]["Authorization"] == "Bearer secret"
    assert followup["allow_redirects"] is False


def test_transport_refuses_cross_origin_redirect_with_auth():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    redirect = _response(302)
    redirect.headers = {"Location": "https://attacker.test/collect"}
    executor._session.request = MagicMock(return_value=redirect)
    prepared = executor.prepare_request(
        {"id": "resource", "method": "GET", "path": "/resources"},
        StateStore({
            "auth_token": "secret",
            "auth_header_prefix": "Bearer",
            "auth_cookies": {"session": "private"},
        }),
        {}, "TEST",
    )

    response = executor._fire_prepared_request(prepared)

    assert response.status_code == 302
    assert executor._session.request.call_count == 1


def test_payload_patch_constrains_one_field_without_replacing_generated_payload():
    planner = MagicMock()
    planner.generate_payload.return_value = (
        {"login": "generated-user", "accessLevel": "middle"},
        "HEURISTIC",
    )
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(201, {"id": "a-1"}))

    result = executor.execute_request(
        {
            "id": "registerAccount",
            "method": "POST",
            "path": "/accounts",
            "inputs": {
                "login": {"in": "body", "original": "login"},
                "accessLevel": {"in": "body", "original": "accessLevel"},
            },
        },
        StateStore(),
        payload_patch={"accessLevel": "outer"},
    )

    assert result["sent_payload"] == {
        "login": "generated-user",
        "accessLevel": "outer",
    }
    assert executor._session.request.call_args.kwargs["json"]["accessLevel"] == "outer"


def test_prepare_multipart_sends_binary_file_and_text_fields_separately():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    node = {
        "id": "uploadVideo",
        "method": "POST",
        "path": "/videos",
        "content_type": "multipart/form-data",
        "inputs": {
            "title": {"original": "title", "in": "body", "type": "string"},
            "video": {
                "original": "video", "in": "body", "type": "string",
                "format": "binary", "is_file": True, "content_type": "video/mp4",
            },
        },
    }

    prepared = executor.prepare_request(
        node, StateStore(),
        {"title": "Demo", "video": {"$artifact": "builtin_valid_fixture"}},
        "HEURISTIC",
    )

    assert prepared.form_body == {"title": "Demo"}
    filename, content, mime = prepared.files["video"]
    assert filename.endswith(".mp4")
    assert isinstance(content, bytes) and content.startswith(b"\x00\x00\x00\x18ftyp")
    assert mime == "video/mp4"
    assert prepared.file_metadata["video"]["size"] == len(content)
    assert "sha256" in prepared.file_metadata["video"]


def test_fire_multipart_lets_requests_generate_boundary():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    executor._session.request = MagicMock(return_value=_response())
    prepared = executor.prepare_request(
        {
            "id": "uploadImage", "method": "POST", "path": "/images",
            "content_type": "multipart/form-data",
            "inputs": {
                "image": {"original": "image", "in": "body", "is_file": True,
                          "format": "binary", "content_type": "image/png"}
            },
        },
        StateStore(), {"image": {"$artifact": "builtin_valid_fixture"}}, "TEST",
    )
    prepared.headers["Content-Type"] = "multipart/form-data"

    executor._fire_prepared_request(prepared)

    kwargs = executor._session.request.call_args.kwargs
    assert "Content-Type" not in kwargs["headers"]
    assert kwargs["files"]["image"][2] == "image/png"


def test_prepare_raw_binary_body():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    prepared = executor.prepare_request(
        {
            "id": "uploadRawVideo", "method": "POST", "path": "/raw-video",
            "content_type": "video/mp4",
            "inputs": {
                "body": {"original": "body", "in": "body", "is_file": True,
                         "format": "binary", "content_type": "video/mp4"}
            },
        },
        StateStore(), {"body": {"$artifact": "builtin_valid_fixture"}}, "TEST",
    )

    assert prepared.raw_body.startswith(b"\x00\x00\x00\x18ftyp")
    assert prepared.headers["Content-Type"] == "video/mp4"
    assert prepared.json_body is None


def test_declared_query_auth_uses_matching_state_value_only():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    state = StateStore({"openId": "actor-open-id"})
    declared = {
        "id": "feed", "method": "GET", "path": "/feed",
        "declared_auth_transports": [{
            "scheme_name": "OpenIdAuth", "kind": "query",
            "name": "openId", "prefix": "", "source": "openapi",
        }],
    }

    prepared = executor.prepare_request(declared, state, {}, "NONE")
    undeclared = executor.prepare_request(
        {"id": "profile", "method": "GET", "path": "/profile"}, state, {}, "NONE"
    )

    assert prepared.query_params == {"openId": "actor-open-id"}
    assert undeclared.query_params == {}


def test_set_cookie_becomes_actor_scoped_auth_transport():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"username": "alice", "password": "secret"}, "TEST")
    executor = RequestExecutor("https://target.test", planner=planner)
    response = _response(200, {"id": 1})
    response.cookies = RequestsCookieJar()
    response.cookies.set("memos_session", "cookie-alice")
    executor._session.request = MagicMock(return_value=response)
    state = StateStore({"actor_id": "alice"})

    executor.execute_request(
        {"id": "signin", "method": "POST", "path": "/auth/signin", "inputs": {}},
        state,
        allow_repair=False,
    )
    prepared = executor.prepare_request(
        {"id": "me", "method": "GET", "path": "/user/me"}, state, {}, "NONE"
    )

    assert state.get("auth_cookies") == {"memos_session": "cookie-alice"}
    assert prepared.cookies == {"memos_session": "cookie-alice"}
    assert any(
        t.kind == "cookie" and t.name == "memos_session" and t.value == "cookie-alice"
        for t in state.get_auth_transports()
    )
    assert state.get_auth_context()["transport_kinds"] == ["cookie"]
    assert state.get_auth_context()["transport_sources"] == ["SET_COOKIE"]


def test_shared_session_cookie_jar_is_cleared_between_actor_requests():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    executor._session.cookies.set("memos_session", "owner-cookie")
    executor._session.request = MagicMock(return_value=_response())
    prepared = executor.prepare_request(
        {"id": "me", "method": "GET", "path": "/me"},
        StateStore({"actor_id": "user-b", "auth_cookies": {"memos_session": "user-b-cookie"}}),
        {}, "NONE",
    )

    executor._fire_prepared_request(prepared)

    kwargs = executor._session.request.call_args.kwargs
    assert kwargs["cookies"] == {"memos_session": "user-b-cookie"}
    assert executor._session.cookies.get_dict() == {}


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


def test_http_200_with_fail_body_is_application_failure():
    planner = MagicMock()
    planner.generate_payload.return_value = (
        {"username": "duplicate-user", "password": "secret"},
        "HEURISTIC",
    )
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(
        200,
        {"status": "fail", "message": "User already exists. Please log in."},
    ))
    state = StateStore()

    result = executor.execute_request(
        {"id": "registerUser", "method": "POST", "path": "/register", "inputs": {}},
        state,
        allow_repair=False,
    )

    assert result["status"] == 200
    assert result["successful"] is False
    assert result["semantic_failure"] is True
    assert "status='fail'" in result["outcome_reason"]
    assert state.get("username") is None


def test_request_and_response_logs_redact_credentials(caplog):
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    executor._session.request = MagicMock(return_value=_response(400, {
        "access_token": "response-secret-token",
        "message": "invalid password",
    }))

    with caplog.at_level("DEBUG", logger="executor"):
        executor.execute_request(
            {"id": "login", "method": "POST", "path": "/login", "inputs": {}},
            StateStore(),
            payload_override={"password": "request-secret-password"},
            payload_source_override="TEST",
            allow_repair=False,
        )

    assert "request-secret-password" not in caplog.text
    assert "response-secret-token" not in caplog.text
    assert "***REDACTED***" in caplog.text


def test_uses_declared_openapi_2xx_statuses():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"email": "new@example.test"}, "HEURISTIC")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(200, {"status": "success"}))

    result = executor.execute_request(
        {
            "id": "updateEmail",
            "method": "PUT",
            "path": "/email",
            "inputs": {},
            "expected_success_statuses": ["204"],
        },
        StateStore(),
        allow_repair=False,
    )

    assert result["status"] == 200
    assert result["successful"] is False
    assert "not an expected OpenAPI success status" in result["outcome_reason"]


def test_transport_rebinds_repair_path_to_authenticated_principal():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    executor._session.request = MagicMock(return_value=_response(204))
    state = StateStore({
        "auth_token": "token-a",
        "username": "owner-a",
    })
    state.update("username", "observed-user-b")

    result = executor.execute_request(
        {
            "id": "updateEmail",
            "method": "PUT",
            "path": "/users/{username}/email",
            "inputs": {
                "username": {"original": "username", "in": "path"},
                "email": {"original": "email", "in": "body"},
            },
            "expected_success_statuses": ["204"],
        },
        state,
        payload_override={"username": "user-b", "email": "new@example.test"},
        payload_source_override="LLM_REPAIR",
        allow_repair=False,
    )

    assert result["url"] == "https://target.test/users/owner-a/email"
    assert result["sent_payload"]["username"] == "owner-a"


def test_cookie_authenticated_repair_path_stays_bound_to_principal():
    executor = RequestExecutor("https://target.test", planner=MagicMock())
    executor._session.request = MagicMock(return_value=_response(204))
    state = StateStore({
        "auth_cookies": {"session": "owner-session"},
        "username": "owner-a",
    })
    state.update("username", "observed-user-b")

    result = executor.execute_request(
        {
            "id": "updateEmail", "method": "PUT",
            "path": "/users/{username}/email",
            "inputs": {
                "username": {"original": "username", "in": "path"},
                "email": {"original": "email", "in": "body"},
            },
            "expected_success_statuses": ["204"],
        },
        state,
        payload_override={"username": "user-b", "email": "new@example.test"},
        payload_source_override="LLM_REPAIR",
        allow_repair=False,
    )

    assert result["url"] == "https://target.test/users/owner-a/email"
    assert result["sent_cookies"] == {"session": "owner-session"}


def test_auth_state_mismatch_recovers_identity_before_retry():
    planner = MagicMock()
    planner.generate_payload.return_value = ({}, "NONE")
    executor = RequestExecutor("https://target.test", planner=planner)

    missing_user = MagicMock()
    missing_user.status_code = 500
    missing_user.text = "AttributeError: 'NoneType' object has no attribute 'username'"
    missing_user.json.side_effect = ValueError("not json")
    recovered_response = _response(200, {
        "username": "alice",
        "email": "alice@example.test",
    })
    executor._session.request = MagicMock(side_effect=[missing_user, recovered_response])

    state = StateStore({
        "actor_id": "alice-actor",
        "auth_token": "stale-token",
        "username": "alice",
    })

    def recover(auth_state, _api_node, _failed_result):
        auth_state.update("auth_token", "fresh-token")
        auth_state.mark_auth_identity(True, "identity recreated")
        return True

    executor.auth_recovery_handler = recover
    result = executor.execute_request(
        {"id": "getMe", "method": "GET", "path": "/me", "inputs": {}},
        state,
    )

    assert executor._session.request.call_count == 2
    assert result["successful"] is True
    assert result["auth_recovery"]["recovered"] is True
    assert state.get("auth_token") == "fresh-token"
    assert state.get_auth_context()["exists"] is True


def test_missing_user_in_cookie_session_triggers_relogin_and_retry():
    planner = MagicMock()
    planner.generate_payload.return_value = ({}, "NONE")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(side_effect=[
        _response(401, {"error": "Missing user in session"}),
        _response(200, {"data": {}}),
    ])
    state = StateStore({
        "actor_id": "owner-a",
        "auth_cookies": {"memos_session": "stale-session"},
    })

    def recover(auth_state, _api_node, _failed_result):
        auth_state.update("auth_cookies", {"memos_session": "fresh-session"})
        return True, "session refreshed"

    executor.auth_recovery_handler = recover
    result = executor.execute_request({
        "id": "POST__system_vacuum", "method": "POST",
        "path": "/system/vacuum", "inputs": {},
        "expected_success_statuses": ["200"],
    }, state)

    assert executor._session.request.call_count == 2
    assert executor._session.request.call_args_list[0].kwargs.get("json") is None
    assert executor._session.request.call_args_list[1].kwargs.get("json") is None
    assert result["successful"] is True
    assert result["auth_recovery"]["recovered"] is True


def test_generic_server_error_does_not_trigger_auth_recovery():
    planner = MagicMock()
    planner.generate_payload.return_value = ({}, "NONE")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(
        500, {"error": "database timeout"}
    ))
    executor.auth_recovery_handler = MagicMock(return_value=True)

    result = executor.execute_request(
        {"id": "listThings", "method": "GET", "path": "/things", "inputs": {}},
        StateStore({"auth_token": "valid-token", "username": "alice"}),
    )

    assert result["status"] == 500
    executor.auth_recovery_handler.assert_not_called()


def test_principal_user_not_found_triggers_auth_recovery_for_get():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"username": "deleted-user"}, "HEURISTIC")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(side_effect=[
        _response(404, {"status": "fail", "message": "User not found"}),
        _response(200, {"username": "recreated-user", "email": "new@example.test"}),
    ])
    state = StateStore({
        "actor_id": "owner-a",
        "auth_token": "stale-token",
        "username": "deleted-user",
    })

    def recover(auth_state, _api_node, _failed_result):
        replacement = StateStore({
            "actor_id": "owner-a",
            "auth_token": "fresh-token",
            "username": "recreated-user",
        })
        replacement.mark_auth_identity(True, "identity recreated")
        auth_state.replace_auth_context_from(replacement)
        return True, "identity recreated"

    executor.auth_recovery_handler = recover
    result = executor.execute_request(
        {
            "id": "getUser",
            "method": "GET",
            "path": "/users/{username}",
            "inputs": {"username": {"original": "username", "in": "path"}},
        },
        state,
    )

    assert executor._session.request.call_count == 2
    assert result["successful"] is True
    assert result["url"] == "https://target.test/users/recreated-user"
    assert result["auth_recovery"]["recovered"] is True


def test_unrelated_missing_user_does_not_recreate_current_actor():
    planner = MagicMock()
    planner.generate_payload.return_value = ({"username": "somebody-else"}, "HEURISTIC")
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(return_value=_response(
        404, {"status": "fail", "message": "User not found"}
    ))
    executor.auth_recovery_handler = MagicMock(return_value=True)

    result = executor.execute_request(
        {
            "id": "getUser",
            "method": "GET",
            "path": "/users/{username}",
            "inputs": {"username": {"original": "username", "in": "path"}},
        },
        StateStore({"auth_token": "valid-token", "username": "owner-user"}),
        # ATTACKER source prevents principal rebinding and represents an
        # intentional lookup of a different identity.
        payload_override={"username": "somebody-else"},
        payload_source_override="ATTACKER_ID_SUBSTITUTION",
        allow_repair=False,
    )

    assert result["status"] == 404
    executor.auth_recovery_handler.assert_not_called()


def test_successful_create_captures_request_values_for_downstream_reads():
    planner = MagicMock()
    planner.generate_payload.return_value = (
        {"book_title": "The Great Gatsby", "secret": "secret-value"},
        "OLLAMA_ARCHITECT",
    )
    executor = RequestExecutor("https://target.test", planner=planner)
    executor._session.request = MagicMock(
        return_value=_response(200, {"status": "success", "message": "Book has been added."})
    )
    state = StateStore()

    result = executor.execute_request(
        {
            "id": "api_views.books.add_new_book",
            "method": "POST",
            "path": "/books/v1",
            "inputs": {
                "book_title": {"original": "book_title", "in": "body", "required": True},
                "secret": {"original": "secret", "in": "body", "required": True},
            },
        },
        state,
    )

    assert result["status"] == 200
    assert result["state_transition"] is True
    assert state.get("book_title") == "The Great Gatsby"
