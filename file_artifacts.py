"""Safe, deterministic upload fixtures used by generated API requests."""

import base64
import hashlib
import mimetypes
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class FileArtifact:
    filename: str
    content_type: str
    content: bytes
    source: str = "BUILTIN_FIXTURE"

    def metadata(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": len(self.content),
            "sha256": hashlib.sha256(self.content).hexdigest(),
            "source": self.source,
        }


class FileArtifactProvider:
    """Resolve upload fields without allowing arbitrary local-file reads."""

    MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    _PNG = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
    _PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    _MP4 = (
        b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"
        b"\x00\x00\x00\x08mdat"
    )

    def resolve(self, field_name: str, meta: Dict[str, Any], requested: Any = None) -> FileArtifact:
        requested_dict = requested if isinstance(requested, dict) else {}
        requested_mime = requested_dict.get("content_type")
        requested_name = requested_dict.get("filename")
        content_type = str(
            requested_mime
            or meta.get("content_type")
            or meta.get("content_media_type")
            or self._infer_content_type(field_name, requested_name)
        ).split(",", 1)[0].strip()

        content, extension = self._fixture_for(content_type)
        filename = self._safe_filename(requested_name or f"{field_name}{extension}")
        if len(content) > self.MAX_UPLOAD_BYTES:
            raise ValueError("Upload fixture exceeds the configured size limit")
        return FileArtifact(filename, content_type, content)

    @staticmethod
    def _safe_filename(value: str) -> str:
        filename = str(value).replace("\\", "/").rsplit("/", 1)[-1]
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
        return filename[:120] or "upload.bin"

    @staticmethod
    def _infer_content_type(field_name: str, filename: Optional[str]) -> str:
        if filename:
            guessed, _ = mimetypes.guess_type(filename)
            if guessed:
                return guessed
        name = field_name.lower()
        if "video" in name: return "video/mp4"
        if "image" in name or "photo" in name or "avatar" in name: return "image/png"
        if "pdf" in name or "document" in name: return "application/pdf"
        if "text" in name: return "text/plain"
        return "application/octet-stream"

    def _fixture_for(self, content_type: str):
        mime = content_type.lower()
        if mime.startswith("image/"):
            return self._PNG, ".png"
        if mime.startswith("video/"):
            return self._MP4, ".mp4"
        if mime == "application/pdf":
            return self._PDF, ".pdf"
        if mime.startswith("text/"):
            return b"OPG upload fixture\n", ".txt"
        return b"OPG_BINARY_FIXTURE", ".bin"
