import json
from unittest.mock import MagicMock

from graph_builder import DependencyGraphBuilder
from llm_planner import LLMPlanner
from rule_inference_layer import RuleInferenceLayer
from spec_parser import SpecParser
from state_store import StateStore


def _book_spec():
    return {
        "openapi": "3.0.0",
        "paths": {
            "/books/v1": {
                "post": {
                    "operationId": "api_views.books.add_new_book",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["book_title", "secret"],
                                    "properties": {
                                        "book_title": {"type": "string"},
                                        "secret": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "message": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    },
                }
            },
            "/books/v1/{book_title}": {
                "get": {
                    "operationId": "api_views.books.get_by_title",
                    "parameters": [
                        {
                            "name": "book_title",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "book"}},
                }
            },
        },
    }


def test_create_request_fields_become_passthrough_outputs(tmp_path):
    spec_path = tmp_path / "books.json"
    spec_path.write_text(json.dumps(_book_spec()), encoding="utf-8")
    operations = SpecParser(str(spec_path)).extract_operations()
    add_book = next(op for op in operations if op["id"].endswith("add_new_book"))

    assert add_book["outputs"]["book_title"]["_request_passthrough"] is True
    assert add_book["expected_success_statuses"] == ["200"]


def test_parser_accepts_all_declared_2xx_success_codes(tmp_path):
    spec = _book_spec()
    spec["paths"]["/books/v1"]["post"]["responses"] = {
        "201": {"description": "created"},
        "202": {"description": "accepted"},
        "204": {"description": "no content"},
        "400": {"description": "bad request"},
    }
    spec_path = tmp_path / "statuses.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")

    operation = next(
        op for op in SpecParser(str(spec_path)).extract_operations()
        if op["id"].endswith("add_new_book")
    )

    assert operation["expected_success_statuses"] == ["201", "202", "204"]


def test_odg_connects_add_book_to_get_by_title(tmp_path):
    spec_path = tmp_path / "books.json"
    spec_path.write_text(json.dumps(_book_spec()), encoding="utf-8")
    operations = SpecParser(str(spec_path)).extract_operations()
    planner = MagicMock()
    planner.get_semantic_cache.return_value = None
    planner.get_cluster_map.return_value = {}
    planner.classify_unknown_fields.return_value = {}
    planner.cluster_identities.return_value = {}
    rules = RuleInferenceLayer(planner, operations)
    graph = DependencyGraphBuilder(operations, rules, planner).build_scientific_odg(
        str(tmp_path / "books.dot")
    )

    outgoing = graph["api_views.books.add_new_book"]
    edge = next(edge for edge in outgoing if edge["to"] == "api_views.books.get_by_title")
    assert any(dep["consumer_field"] == "book_title" for dep in edge["dependencies"])


def test_context_binding_overrides_invented_get_title():
    planner = LLMPlanner.__new__(LLMPlanner)
    state = StateStore({"book_title": "The Great Gatsby"})
    node = {
        "id": "api_views.books.get_by_title",
        "method": "GET",
        "path": "/books/v1/{book_title}",
        "inputs": {
            "book_title": {
                "original": "book_title",
                "in": "path",
                "required": True,
            }
        },
    }

    bound = planner._apply_context_bindings(
        {"book_title": "Fuzzing API"}, node, state
    )

    assert bound["book_title"] == "The Great Gatsby"


def test_optional_post_reference_prefers_exact_actor_state_over_llm_and_fuzzy_edge():
    planner = LLMPlanner.__new__(LLMPlanner)
    state = StateStore({
        "actor_id": "actor-a",
        "artifactId": 42,
        "artifactList": [7, 8],
    })
    node = {
        "id": "attachArtifact",
        "method": "POST",
        "path": "/containers/{containerId}/artifacts",
        "inputs": {
            "artifactid": {
                "original": "artifactId",
                "in": "body",
                "type": "integer",
                "required": False,
            }
        },
    }

    bound = planner._apply_context_bindings(
        {"artifactId": 123},
        node,
        state,
        edge_deps=[{
            "producer_field": "artifactList",
            "consumer_field": "artifactId",
        }],
    )

    assert bound["artifactId"] == 42
