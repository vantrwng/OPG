from actor_bootstrapper import ActorBootstrapper
from state_store import StateStore


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def execute_request(self, operation, state, allow_repair=True):
        self.calls.append((operation["id"], state.get("actor_id")))
        if operation["id"] == "registerUser":
            actor = state.get("actor_id")
            state.update("email", f"{actor}@example.test")
            state.update("password", "StrongPassword123!")
            return {"status": 201, "response_text": "", "raw_response": {"id": actor}}
        state.update("auth_token", f"token-{state.get('actor_id')}")
        return {"status": 200, "response_text": "", "raw_response": {"token": state.get("auth_token")}}


OPERATIONS = [
    {
        "id": "requestOtp",
        "method": "POST",
        "path": "/auth/otp",
        "inputs": {"email": {"type": "string"}},
    },
    {
        "id": "registerUser",
        "method": "POST",
        "path": "/auth/signup",
        "inputs": {
            "email": {"type": "string"},
            "password": {"type": "string"},
        },
    },
    {
        "id": "loginUser",
        "method": "POST",
        "path": "/auth/login",
        "inputs": {
            "email": {"type": "string"},
            "password": {"type": "string"},
        },
    },
]


def test_discovers_signup_and_login_without_selecting_otp():
    bootstrapper = ActorBootstrapper(OPERATIONS, FakeExecutor())
    signup, login = bootstrapper.discover_auth_operations()
    assert signup["id"] == "registerUser"
    assert login["id"] == "loginUser"


def test_bootstraps_two_isolated_authenticated_actors():
    executor = FakeExecutor()
    result = ActorBootstrapper(OPERATIONS, executor).bootstrap(
        {"auth_header_name": "Authorization", "auth_header_prefix": "Bearer"}
    )

    assert result.success is True
    assert result.owner_state.get("actor_id") == "owner_a"
    assert result.owner_state.get("auth_token") == "token-owner_a"
    assert result.actors.require("user_b").auth_token == "token-user_b"
    assert result.actors.require("anonymous").auth_token == ""
    assert executor.calls == [
        ("registerUser", "owner_a"),
        ("loginUser", "owner_a"),
        ("registerUser", "user_b"),
        ("loginUser", "user_b"),
    ]


def test_bootstrap_rejects_http_200_application_failure():
    class FailingSignupExecutor:
        def execute_request(self, operation, state, allow_repair=True):
            return {
                "status": 200,
                "raw_response": {
                    "status": "fail",
                    "message": "User already exists. Please log in.",
                },
                "response_text": '{"status":"fail"}',
            }

    result = ActorBootstrapper(OPERATIONS, FailingSignupExecutor()).bootstrap()

    assert result.success is False
    assert "signup failed with HTTP 200" in result.errors[0]


def test_fails_cleanly_when_auth_operations_are_missing():
    result = ActorBootstrapper([], FakeExecutor()).bootstrap()
    assert result.success is False
    assert "signup" in result.errors[0].lower()


def test_recovery_recreates_identity_when_relogin_fails():
    class RecoveryExecutor:
        def __init__(self):
            self.login_calls = 0

        def execute_request(self, operation, state, **_kwargs):
            if operation["id"] == "loginUser":
                self.login_calls += 1
                if self.login_calls == 1:
                    return {
                        "status": 200,
                        "successful": False,
                        "raw_response": {"status": "fail", "message": "User not found"},
                        "response_text": '{"status":"fail"}',
                    }
                assert state.get_actor_identity("username") == "recreated-user"
                state.update("auth_token", "token-recreated")
                return {"status": 200, "successful": True, "raw_response": {"token": "token-recreated"}}

            state.update("email", "recreated@example.test")
            state.update("username", "recreated-user")
            state.update("password", "RecreatedPassword123!")
            return {"status": 201, "successful": True, "raw_response": {"status": "success"}}

    state = StateStore({
        "actor_id": "owner_a",
        "auth_token": "stale-token",
        "email": "deleted@example.test",
        "username": "deleted-user",
        "password": "OldPassword123!",
    })
    recovered, reason = ActorBootstrapper(
        OPERATIONS, RecoveryExecutor()
    ).recover_actor(state)

    assert recovered is True
    assert reason == "identity recreated"
    assert state.get("auth_token") == "token-recreated"
    assert state.get("email") == "recreated@example.test"
    assert state.get_auth_context()["exists"] is True


def test_preflight_verifies_token_with_current_user_endpoint():
    operations = OPERATIONS + [{
        "id": "getCurrentUser",
        "method": "GET",
        "path": "/me",
        "inputs": {},
    }]

    class IdentityExecutor:
        def execute_request(self, operation, state, **_kwargs):
            assert operation["id"] == "getCurrentUser"
            return {
                "status": 200,
                "successful": True,
                "raw_response": {"username": "alice"},
            }

    state = StateStore({"auth_token": "token-alice", "username": "alice"})
    bootstrapper = ActorBootstrapper(operations, IdentityExecutor())

    assert bootstrapper.discover_identity_operation()["id"] == "getCurrentUser"
    verified, reason = bootstrapper.validate_actor(state)

    assert verified is True
    assert reason == "identity verified"
    assert state.get_auth_context()["exists"] is True


def test_bootstrap_spreads_declared_roles_and_trusts_effective_server_role():
    operations = [
        {
            "id": "registerAccount",
            "method": "POST",
            "path": "/accounts/register",
            "inputs": {
                "login": {"original": "login", "type": "string"},
                "password": {"original": "password", "type": "string"},
                "accessLevel": {
                    "original": "accessLevel",
                    "type": "string",
                    "enum": ["tier-one", "tier-two", "tier-three"],
                },
            },
        },
        {
            "id": "loginAccount",
            "method": "POST",
            "path": "/accounts/login",
            "inputs": {
                "login": {"original": "login", "type": "string"},
                "password": {"original": "password", "type": "string"},
            },
        },
    ]

    class RoleAwareExecutor:
        def __init__(self):
            self.requested_roles = []

        def execute_request(self, operation, state, **kwargs):
            if operation["id"] == "registerAccount":
                requested = kwargs.get("payload_patch", {}).get("accessLevel")
                self.requested_roles.append(requested)
                state.update("login", f"{state.get('actor_id')}@example.test")
                state.update("password", "StrongPassword123!")
                return {
                    "status": 201,
                    "successful": True,
                    "url": "https://target.test/accounts/register",
                    "sent_payload": {
                        "login": state.get("login"),
                        "password": state.get("password"),
                        "accessLevel": requested,
                    },
                    "raw_response": {
                        "data": {"accessLevel": f"effective-{requested}"},
                    },
                }
            state.update("auth_token", f"token-{state.get('actor_id')}")
            return {
                "status": 200,
                "successful": True,
                "sent_payload": {
                    "login": state.get("login"),
                    "password": state.get("password"),
                },
                "raw_response": {"accessLevel": state.get("actor_role")},
                "sent_headers": {"Authorization": "secret-token"},
            }

    executor = RoleAwareExecutor()
    result = ActorBootstrapper(operations, executor).bootstrap()

    assert result.success is True
    assert executor.requested_roles == ["tier-one", "tier-three", "tier-three"]
    assert result.actors.require("owner_a").role == "effective-tier-one"
    assert result.actors.require("user_b").role == "effective-tier-three"
    assert result.actors.require("user_c").role == "effective-tier-three"
    assert result.owner_state.get("actor_id") == "user_b"
    assert [event["stage"] for event in result.events] == [
        "signup", "signin", "signup", "signin", "signup", "signin",
    ]
    assert result.events[0]["request_payload"]["password"] == "***"
    assert result.events[0]["requested_role"] == "tier-one"
    assert result.events[0]["effective_role"] == "effective-tier-one"


def test_second_actor_falls_back_to_authenticated_schema_compatible_provisioning():
    operations = [
        {
            "id": "registerSelf",
            "method": "POST",
            "path": "/identity/enroll",
            "inputs": {
                "loginName": {"original": "loginName", "type": "string"},
                "passphrase": {"original": "passphrase", "type": "string"},
                "accessLevel": {
                    "original": "accessLevel",
                    "type": "string",
                    "enum": ["level-a", "level-b", "level-c"],
                },
            },
        },
        {
            "id": "authenticatePrincipal",
            "method": "POST",
            "path": "/identity/session",
            "inputs": {
                "loginName": {"original": "loginName", "type": "string"},
                "passphrase": {"original": "passphrase", "type": "string"},
            },
        },
        {
            "id": "provisionPrincipal",
            "method": "POST",
            "path": "/management/principals",
            "security_required": True,
            "inputs": {
                "loginName": {"original": "loginName", "type": "string", "required": True},
                "passphrase": {"original": "passphrase", "type": "string", "required": True},
                "accessLevel": {
                    "original": "accessLevel",
                    "type": "string",
                    "enum": ["level-a", "level-b", "level-c"],
                },
            },
        },
    ]

    class InitialPrincipalOnlyExecutor:
        def __init__(self):
            self.signup_calls = 0
            self.calls = []

        def execute_request(self, operation, state, **kwargs):
            self.calls.append((operation["id"], state.get("actor_id")))
            patch = kwargs.get("payload_patch", {})
            if operation["id"] == "registerSelf":
                self.signup_calls += 1
                payload = {
                    "loginName": f"login-{state.get('actor_id')}",
                    "passphrase": "StrongPassphrase123!",
                    "accessLevel": patch.get("accessLevel"),
                }
                state.update("loginName", payload["loginName"])
                state.update("passphrase", payload["passphrase"])
                if self.signup_calls > 1:
                    return {
                        "status": 403,
                        "successful": False,
                        "sent_payload": payload,
                        "raw_response": {"message": "initial principal already exists"},
                    }
                return {
                    "status": 201,
                    "successful": True,
                    "sent_payload": payload,
                    "raw_response": {"accessLevel": patch.get("accessLevel")},
                }
            if operation["id"] == "provisionPrincipal":
                assert state.get("actor_id") == "owner_a"
                assert state.get("auth_token") == "token-owner_a"
                return {
                    "status": 201,
                    "successful": True,
                    "sent_payload": dict(patch),
                    "raw_response": {"accessLevel": patch["accessLevel"]},
                }
            state.update("auth_token", f"token-{state.get('actor_id')}")
            return {
                "status": 200,
                "successful": True,
                "sent_payload": {
                    "loginName": state.get("loginName"),
                    "passphrase": state.get("passphrase"),
                },
                "raw_response": {"accessLevel": state.get("actor_role")},
            }

    executor = InitialPrincipalOnlyExecutor()
    result = ActorBootstrapper(operations, executor).bootstrap()

    assert result.success is True
    assert result.actors.require("owner_a").role == "level-a"
    assert result.actors.require("user_b").role == "level-c"
    assert result.actors.require("user_b").auth_token == "token-user_b"
    assert result.actors.require("user_b").credentials["loginName"] == "login-user_b"
    assert result.actors.require("user_b").credentials["passphrase"] == "StrongPassphrase123!"
    assert result.actors.require("user_c").role == "level-c"
    assert result.owner_state.get("actor_id") == "user_b"
    assert executor.calls == [
        ("registerSelf", "owner_a"),
        ("authenticatePrincipal", "owner_a"),
        ("registerSelf", "user_b"),
        ("provisionPrincipal", "owner_a"),
        ("authenticatePrincipal", "user_b"),
        ("registerSelf", "user_c"),
        ("provisionPrincipal", "owner_a"),
        ("authenticatePrincipal", "user_c"),
    ]
    assert [event["stage"] for event in result.events] == [
        "signup", "signin", "signup", "provision", "signin",
        "signup", "provision", "signin",
    ]
    assert result.events[3]["actor_id"] == "user_b"
    assert result.events[3]["performed_by"] == "owner_a"


def test_unknown_roles_are_not_selected_as_a_same_role_pair():
    executor = FakeExecutor()
    result = ActorBootstrapper(OPERATIONS, executor).bootstrap()

    assert result.success is True
    assert result.owner_state.get("actor_id") == "owner_a"
    assert [actor.actor_id for actor in result.actors.all()] == [
        "owner_a", "user_b", "anonymous",
    ]
