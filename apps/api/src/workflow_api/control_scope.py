"""Private tenant/workspace key qualification for the synthetic control plane."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SCOPE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_KEY_VERSION = "whscope1|"
_MAX_PUBLIC_ID_LENGTH = 256


@dataclass(frozen=True, slots=True)
class TenantWorkspaceScope:
    """One exact pseudonymous tenant and workspace authorization scope."""

    tenant_id: str
    workspace_id: str

    def __post_init__(self) -> None:
        _validate_scope(self)


def _validate_scope(scope: TenantWorkspaceScope) -> None:
    if type(scope) is not TenantWorkspaceScope:
        raise TypeError("scope must use the exact tenant/workspace contract type")
    for value, name in (
        (scope.tenant_id, "tenant_id"),
        (scope.workspace_id, "workspace_id"),
    ):
        if not isinstance(value, str) or not _SCOPE_ID_PATTERN.fullmatch(value):
            raise ValueError(f"{name} must be an exact lowercase bounded identifier")


def _scope_prefix(scope: TenantWorkspaceScope) -> str:
    _validate_scope(scope)
    return _KEY_VERSION + _segment(scope.tenant_id) + _segment(scope.workspace_id)


def _qualify(scope: TenantWorkspaceScope, object_kind: str, public_id: str) -> str:
    """Return an injective internal key without delimiter-concatenation ambiguity."""

    kind_prefix = _kind_prefix(scope, object_kind)
    if (
        not isinstance(public_id, str)
        or not public_id.strip()
        or len(public_id) > _MAX_PUBLIC_ID_LENGTH
    ):
        raise ValueError("public identifier must be a non-empty bounded string")
    return kind_prefix + _segment(public_id)


def _kind_prefix(scope: TenantWorkspaceScope, object_kind: str) -> str:
    if not isinstance(object_kind, str) or not _KIND_PATTERN.fullmatch(object_kind):
        raise ValueError("object kind must be an exact bounded identifier")
    return _scope_prefix(scope) + _segment(object_kind)


def _unqualify(
    scope: TenantWorkspaceScope,
    object_kind: str,
    internal_key: str,
) -> str:
    """Validate the exact namespace and return only the caller-visible identifier."""

    prefix = _scope_prefix(scope)
    if not isinstance(internal_key, str) or not internal_key.startswith(prefix):
        raise ValueError("internal key is outside the authorized scope")
    offset = len(prefix)
    parsed_kind, offset = _read_segment(internal_key, offset)
    public_id, offset = _read_segment(internal_key, offset)
    if parsed_kind != object_kind or offset != len(internal_key):
        raise ValueError("internal key has an unexpected object kind")
    return public_id


def _segment(value: str) -> str:
    return f"{len(value)}:{value}"


def _read_segment(value: str, offset: int) -> tuple[str, int]:
    separator = value.find(":", offset)
    if separator == -1:
        raise ValueError("invalid internal key")
    length_text = value[offset:separator]
    if not length_text or not length_text.isascii() or not length_text.isdecimal():
        raise ValueError("invalid internal key")
    length = int(length_text)
    start = separator + 1
    end = start + length
    if length < 1 or end > len(value):
        raise ValueError("invalid internal key")
    return value[start:end], end
