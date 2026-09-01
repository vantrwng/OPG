import json

from spec_parser import SpecParser


def test_parser_normalizes_cookie_query_and_bearer_security_schemes(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "components": {
            "securitySchemes": {
                "Session": {"type": "apiKey", "in": "cookie", "name": "memos_session"},
                "OpenId": {"type": "apiKey", "in": "query", "name": "openId"},
                "Jwt": {"type": "http", "scheme": "bearer"},
            }
        },
        "security": [{"Session": [], "OpenId": [], "Jwt": []}],
        "paths": {
            "/me": {
                "get": {
                    "operationId": "getMe",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(spec), encoding="utf-8")

    operation = SpecParser(str(path)).extract_operations()[0]
    transports = {
        (item["kind"], item["name"], item["prefix"])
        for item in operation["declared_auth_transports"]
    }

    assert ("cookie", "memos_session", "") in transports
    assert ("query", "openId", "") in transports
    assert ("header", "Authorization", "Bearer") in transports


def test_openapi_enum_and_default_constraints_survive_input_parsing(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/accounts": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "accessLevel": {
                                            "type": "string",
                                            "enum": ["tier-one", "tier-two"],
                                            "default": "tier-two",
                                        }
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "created"}},
                }
            }
        },
    }
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")

    operation = SpecParser(str(path)).extract_operations()[0]
    field = next(
        meta for meta in operation["inputs"].values()
        if meta.get("original") == "accessLevel"
    )

    assert field["enum"] == ["tier-one", "tier-two"]
    assert field["default"] == "tier-two"
