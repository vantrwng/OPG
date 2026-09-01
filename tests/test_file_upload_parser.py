import json

from spec_parser import SpecParser


def _parse(tmp_path, request_content):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/upload": {
                "post": {
                    "operationId": "uploadMedia",
                    "requestBody": {"required": True, "content": request_content},
                    "responses": {"201": {"description": "created"}},
                }
            }
        },
    }
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return SpecParser(str(path)).extract_operations()[0]


def test_parser_marks_multipart_binary_property_as_file(tmp_path):
    operation = _parse(tmp_path, {
        "multipart/form-data": {
            "schema": {
                "type": "object",
                "required": ["video"],
                "properties": {
                    "title": {"type": "string"},
                    "video": {"type": "string", "format": "binary"},
                },
            },
            "encoding": {"video": {"contentType": "video/mp4"}},
        }
    })

    assert operation["content_type"] == "multipart/form-data"
    assert operation["inputs"]["video"]["is_file"] is True
    assert operation["inputs"]["video"]["content_type"] == "video/mp4"


def test_parser_supports_raw_media_request_body(tmp_path):
    operation = _parse(tmp_path, {
        "video/mp4": {"schema": {"type": "string", "format": "binary"}}
    })

    assert operation["content_type"] == "video/mp4"
    assert operation["inputs"]["body"]["is_file"] is True
