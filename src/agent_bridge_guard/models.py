"""Immutable, canonical domain artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TypeAlias, cast

JSONScalar: TypeAlias = str | int | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]


class PlanIntegrityError(ValueError):
    """Raised when a serialized plan no longer matches its plan ID."""


def _normalize_json(value: object, path: str = "$") -> JSONValue:
    if isinstance(value, float):
        raise TypeError(f"{path}: floating point values are forbidden")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        result: JSONObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path}: JSON object keys must be strings")
            result[key] = _normalize_json(item, f"{path}.{key}")
        return result
    raise TypeError(f"{path}: unsupported JSON value {type(value).__name__}")


def canonical_json(value: object) -> str:
    """Return strict canonical JSON suitable for local artifact hashing."""

    normalized = _normalize_json(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _plan_id(document_without_id: JSONObject) -> str:
    digest = hashlib.sha256(canonical_json(document_without_id).encode()).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True, slots=True)
class Plan:
    """An immutable plan whose ID binds every serialized execution field."""

    plan_id: str
    _document_json: str = field(repr=False)

    @classmethod
    def create(cls, body: dict[str, object], *, schema_version: int = 1) -> Plan:
        normalized = _normalize_json(body)
        if not isinstance(normalized, dict):
            raise TypeError("plan body must be a JSON object")
        if schema_version not in {1, 2}:
            raise ValueError("unsupported plan schema")
        reserved = {"schema_version", "artifact_type", "plan_id"} & normalized.keys()
        if reserved:
            names = ", ".join(sorted(reserved))
            raise ValueError(f"plan body contains reserved fields: {names}")
        document: JSONObject = {
            "schema_version": schema_version,
            "artifact_type": "plan",
            **normalized,
        }
        identifier = _plan_id(document)
        complete: JSONObject = {**document, "plan_id": identifier}
        return cls(plan_id=identifier, _document_json=canonical_json(complete))

    @classmethod
    def parse(cls, value: dict[str, object]) -> Plan:
        normalized = _normalize_json(value)
        if not isinstance(normalized, dict):
            raise TypeError("plan document must be a JSON object")
        supplied = normalized.get("plan_id")
        if not isinstance(supplied, str):
            raise PlanIntegrityError("plan_id is missing")
        document = dict(normalized)
        del document["plan_id"]
        expected = _plan_id(document)
        if supplied != expected:
            raise PlanIntegrityError("plan_id mismatch")
        if document.get("schema_version") not in {1, 2} or document.get("artifact_type") != "plan":
            raise PlanIntegrityError("unsupported plan schema")
        return cls(plan_id=supplied, _document_json=canonical_json(normalized))

    @property
    def schema_version(self) -> int:
        value = self.to_dict().get("schema_version")
        if value not in {1, 2}:
            raise AssertionError("canonical plan has an unsupported schema")
        return cast(int, value)

    def bind_policy(self, binding: dict[str, object]) -> Plan:
        """Return a v2 plan binding the full operator-reviewed trust inputs."""

        if self.schema_version != 1:
            raise ValueError("only an unbound v1 plan can be policy-bound")
        body = self.body()
        if "policy_binding" in body:
            raise ValueError("plan already contains a policy binding")
        body["policy_binding"] = _normalize_json(binding)
        return type(self).create(cast(dict[str, object], body), schema_version=2)

    def to_dict(self) -> JSONObject:
        parsed = json.loads(self._document_json)
        if not isinstance(parsed, dict):
            raise AssertionError("canonical plan must decode to an object")
        return cast(JSONObject, parsed)

    def body(self) -> JSONObject:
        document = self.to_dict()
        del document["plan_id"]
        del document["schema_version"]
        del document["artifact_type"]
        return document
