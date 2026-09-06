from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse


def require_file(path: str | Path) -> Path:
    file_path = Path(path).expanduser().resolve()

    if not file_path.exists():
        raise ValueError(f"File does not exist: {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Expected a file: {file_path}")

    return file_path


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc

    return value


def validate_url(value: str) -> str:
    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"Invalid HTTP/HTTPS URL: {value}")

    return value