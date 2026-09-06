from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(
    path: str | Path,
    chunk_size: int = 1024 * 1024,
) -> str:
    file_path = Path(path)

    digest = hashlib.sha256()

    with file_path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def json_dump(
    data: Any,
    output: str | Path,
) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    return output_path


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent