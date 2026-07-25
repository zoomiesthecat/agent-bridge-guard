"""Explicitly experimental Turnkey capability boundary."""

from __future__ import annotations

import importlib
import os
from collections.abc import Mapping
from dataclasses import dataclass

from .base import SignedTransaction


@dataclass(frozen=True, slots=True)
class TurnkeyCapability:
    experimental: bool = True
    available: bool = False


class TurnkeySigner:
    """Opt-in placeholder for the pinned Turnkey 0.1.0 SDK family.

    The SDK is only imported when this adapter is deliberately constructed, keeping
    the base package free of an optional custody dependency.
    """

    capability = TurnkeyCapability()
    preparation_replay_safe = False

    def __init__(self, organization_id: str, api_public_key: str, api_private_key: str) -> None:
        if not all((organization_id, api_public_key, api_private_key)):
            raise ValueError("Turnkey credentials are required")
        try:
            importlib.import_module("turnkey_api_key_stamper")
            importlib.import_module("turnkey_http")
            importlib.import_module("turnkey_sdk_types")
        except ImportError as error:
            raise RuntimeError(
                "Turnkey support requires the turnkey optional dependency"
            ) from error
        self._organization_id = organization_id
        self._api_public_key = api_public_key
        self._api_private_key = api_private_key

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> TurnkeySigner:
        values = os.environ if environment is None else environment
        return cls(
            values.get("TURNKEY_ORGANIZATION_ID", ""),
            values.get("TURNKEY_API_PUBLIC_KEY", ""),
            values.get("TURNKEY_API_PRIVATE_KEY", ""),
        )

    @property
    def address(self) -> str:
        raise RuntimeError("experimental Turnkey signer requires a configured wallet address")

    def sign_transaction(self, transaction: Mapping[str, object]) -> SignedTransaction:
        del transaction
        raise RuntimeError("experimental Turnkey transaction signing is not enabled")
