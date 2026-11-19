# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real generated-protobuf factory boundary; no client connection or AWS call."""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from openshell._proto import openshell_pb2
from openshell.provider_bootstrap import (
    ProviderBootstrap,
    ProviderBootstrapError,
    profile_sha256,
)
from openshell.provider_bootstrap_profile import (
    BEDROCK_SIGNING_PROFILE_SHA256,
    bedrock_signing_profile,
)
from openshell.sandbox import TlsConfig


class BedrockSigningProfileTest(unittest.TestCase):
    def test_real_export_fresh_copy_semantic_pin_and_sdk_constructor(self):
        def forbidden_operation(*_):
            raise AssertionError("No creation, ownership or RPC operation is expected")

        with patch("openshell.provider_bootstrap.SandboxClient") as client:
            first = bedrock_signing_profile()
            second = bedrock_signing_profile()
            self.assertIs(type(first), openshell_pb2.ProviderProfile)
            self.assertIsNot(first, second)
            self.assertEqual(first, second)
            self.assertEqual(profile_sha256(first), BEDROCK_SIGNING_PROFILE_SHA256)
            client.assert_not_called()

            first.description = "caller mutation"
            self.assertNotEqual(profile_sha256(first), BEDROCK_SIGNING_PROFILE_SHA256)
            self.assertEqual(
                profile_sha256(bedrock_signing_profile()),
                BEDROCK_SIGNING_PROFILE_SHA256,
            )
            second.resource_version = 999
            second.source = "user"
            second.scope = "workspace"
            self.assertEqual(profile_sha256(second), BEDROCK_SIGNING_PROFILE_SHA256)

            arguments = {
                "tls": TlsConfig(Path("ca.pem"), Path("client.pem"), Path("key.pem")),
                "installation_id": "constructor-only-fixture",
                "workspace": "default",
                "expected_profile_sha256": BEDROCK_SIGNING_PROFILE_SHA256,
                "require_installation_current": lambda: None,
                "record_created": forbidden_operation,
                "require_owned": forbidden_operation,
            }
            with self.assertRaises(ProviderBootstrapError):
                ProviderBootstrap(
                    "https://gateway.example:443", profile=first, **arguments
                )
            client.assert_not_called()

            close = Mock()
            client.return_value = SimpleNamespace(close=close)
            bootstrap = ProviderBootstrap(
                "https://gateway.example:443",
                profile=bedrock_signing_profile(),
                **arguments,
            )
            client.assert_called_once()
            bootstrap.close()
            close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
