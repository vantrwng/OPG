import asyncio

from local_mutator import AsyncFuzzEngine, FuzzDictionary


def test_local_mutator_replays_baseline_auth_transports_per_request(monkeypatch):
    captured = []

    class FakeResponse:
        status = 200

        async def text(self):
            return '{"ok":true}'

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def request(self, method, url, **kwargs):
            captured.append((method, url, kwargs))
            return FakeResponse()

    monkeypatch.setattr(
        FuzzDictionary,
        "mutate_payload",
        staticmethod(lambda _payload, _count: [{"name": "mutated"}]),
    )
    monkeypatch.setattr(
        "local_mutator.aiohttp.ClientSession",
        lambda: FakeSession(),
    )

    results = asyncio.run(AsyncFuzzEngine.blast_api(
        url="https://target.test/items",
        method="POST",
        headers={"Authorization": "Bearer actor-token"},
        query={"api_key": "query-secret"},
        cookies={"session_id": "cookie-secret"},
        valid_payload={"name": "valid"},
        num_requests=1,
    ))

    assert results == [{
        "status": 200,
        "text": '{"ok":true}',
        "payload": {"name": "mutated"},
    }]
    assert captured[0][2]["headers"] == {"Authorization": "Bearer actor-token"}
    assert captured[0][2]["params"] == {"api_key": "query-secret"}
    assert captured[0][2]["cookies"] == {"session_id": "cookie-secret"}

