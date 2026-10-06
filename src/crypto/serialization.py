import json
from pathlib import Path
from typing import Any

from .keys import RSAPrivateKey, RSAPublicKey


FORMAT_NAME = "native-rsa-json"
FORMAT_VERSION = 1


def _integer_to_hex(value: int) -> str:
    return format(value, "x")


def _hex_to_integer(value: Any, field: str) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError(f"key field {field!r} must be a hexadecimal string")
    try:
        return int(value, 16)
    except ValueError as error:
        raise ValueError(f"key field {field!r} is not valid hexadecimal") from error


def public_key_to_dict(key: RSAPublicKey) -> dict[str, Any]:
    return {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "type": "public",
        "n": _integer_to_hex(key.n),
        "e": _integer_to_hex(key.e),
    }


def private_key_to_dict(key: RSAPrivateKey) -> dict[str, Any]:
    return {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "type": "private",
        "n": _integer_to_hex(key.n),
        "e": _integer_to_hex(key.e),
        "d": _integer_to_hex(key.d),
        "p": _integer_to_hex(key.p),
        "q": _integer_to_hex(key.q),
    }


def _validate_header(data: dict[str, Any], expected_type: str) -> None:
    if data.get("format") != FORMAT_NAME:
        raise ValueError("unsupported key format")
    if data.get("version") != FORMAT_VERSION:
        raise ValueError("unsupported key format version")
    if data.get("type") != expected_type:
        raise ValueError(f"expected a {expected_type} key")


def public_key_from_dict(data: dict[str, Any]) -> RSAPublicKey:
    _validate_header(data, "public")
    return RSAPublicKey(
        n=_hex_to_integer(data.get("n"), "n"),
        e=_hex_to_integer(data.get("e"), "e"),
    )


def private_key_from_dict(data: dict[str, Any]) -> RSAPrivateKey:
    _validate_header(data, "private")
    return RSAPrivateKey(
        n=_hex_to_integer(data.get("n"), "n"),
        e=_hex_to_integer(data.get("e"), "e"),
        d=_hex_to_integer(data.get("d"), "d"),
        p=_hex_to_integer(data.get("p"), "p"),
        q=_hex_to_integer(data.get("q"), "q"),
    )


def save_public_key(key: RSAPublicKey, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(public_key_to_dict(key), indent=2) + "\n",
        encoding="utf-8",
    )


def save_private_key(key: RSAPrivateKey, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(private_key_to_dict(key), indent=2) + "\n",
        encoding="utf-8",
    )


def _read_json(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("key file must contain a JSON object")
    return data


def load_public_key(path: str | Path) -> RSAPublicKey:
    return public_key_from_dict(_read_json(path))


def load_private_key(path: str | Path) -> RSAPrivateKey:
    return private_key_from_dict(_read_json(path))
