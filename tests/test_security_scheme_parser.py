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


def test_openapi_overlay_adds_hidden_auth_operation_and_bola_hints(tmp_path):
    base = {
        "openapi": "3.0.0",
        "paths": {
            "/users/whoami": {
                "get": {
                    "operationId": "whoami",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    overlay = {
        "x-bola": {"identity_operation": "whoami"},
        "paths": {
            "/login": {
                "post": {
                    "operationId": "login",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "required": ["username", "password"],
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    base_path = tmp_path / "base.json"
    overlay_path = tmp_path / "overlay.json"
    base_path.write_text(json.dumps(base), encoding="utf-8")
    overlay_path.write_text(json.dumps(overlay), encoding="utf-8")

    parser = SpecParser(str(base_path), overlay_path=str(overlay_path))
    operations = {item["id"]: item for item in parser.extract_operations()}

    assert parser.parse_errors == []
    assert parser.get_bola_config()["identity_operation"] == "whoami"
    assert operations["login"]["content_type"] == "application/x-www-form-urlencoded"
    assert {meta["original"] for meta in operations["login"]["inputs"].values()} == {
        "username", "password"
    }
