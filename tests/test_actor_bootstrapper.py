from actor_bootstrapper import ActorBootstrapper


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


def test_fails_cleanly_when_auth_operations_are_missing():
    result = ActorBootstrapper([], FakeExecutor()).bootstrap()
    assert result.success is False
    assert "signup" in result.errors[0].lower()
