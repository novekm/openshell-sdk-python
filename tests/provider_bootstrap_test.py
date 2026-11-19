# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated-protobuf, mock-RPC cases; no channel, secret lookup or AWS call."""

from __future__ import annotations

import threading
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import grpc

from openshell._proto import datamodel_pb2, openshell_pb2
from openshell.provider_bootstrap import (
    BootstrapOperationReceipt,
    GatewayDefaultChainSource,
    ProviderBootstrap,
    ProviderBootstrapError,
    SecretRefreshSource,
    profile_sha256,
)
from openshell.sandbox import TlsConfig


def _profile():
    profile = openshell_pb2.ProviderProfile(
        id="aws-bedrock-signing",
        category=openshell_pb2.PROVIDER_PROFILE_CATEGORY_INFERENCE,
        inference_capable=True,
    )
    for name, env in (
        ("access_key_id", "AWS_ACCESS_KEY_ID"),
        ("secret_access_key", "AWS_SECRET_ACCESS_KEY"),
        ("session_token", "AWS_SESSION_TOKEN"),
    ):
        profile.credentials.add(name=name, env_vars=[env], required=True)
    refresh = profile.credentials[0].refresh
    refresh.strategy = (
        openshell_pb2.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE
    )
    refresh.refresh_before.seconds = 300
    refresh.max_lifetime.seconds = 3600
    for name, required, secret in (
        ("role_arn", True, False),
        ("session_name", False, False),
        ("external_id", False, False),
        ("aws_region", False, False),
        ("aws_access_key_id", False, False),
        ("aws_secret_access_key", False, True),
        ("aws_session_token", False, True),
    ):
        refresh.material.add(name=name, required=required, secret=secret)
    refresh.additional_outputs.add(
        output="secret_access_key", credential="secret_access_key"
    )
    refresh.additional_outputs.add(output="session_token", credential="session_token")
    return profile


class _RpcFailure(grpc.RpcError):
    def __init__(self, status):
        self.status = status

    def code(self):
        return self.status

    def __str__(self):
        raise AssertionError("bootstrap must not inspect exception prose")


class _Stub:
    def __init__(self, profile):
        self.profile = openshell_pb2.ProviderProfile()
        self.profile.CopyFrom(profile)
        self.profile.scope = "workspace"
        self.profile.resource_version = 1
        self.support = True
        self.provider = None
        self.calls = []
        self.writes = 0
        self.fail_create = False
        self.replace_during_rotate = False
        self.after_create = lambda: None
        self.after_refresh = lambda: None
        self.after_import = lambda: None

    def _capture(self, method, request):
        self.calls.append(
            (method, type(request).FromString(request.SerializeToString()))
        )

    def ListProviderProfiles(self, request, **_):
        self._capture("support", request)
        return openshell_pb2.ListProviderProfilesResponse(
            supports_refresh_resource_version_preconditions=self.support
        )

    def GetProviderProfile(self, request, **_):
        self._capture("profile", request)
        return openshell_pb2.ProviderProfileResponse(profile=self.profile)

    def ImportProviderProfiles(self, request, **_):
        self._capture("import", request)
        self.writes += 1
        response = openshell_pb2.ImportProviderProfilesResponse(
            imported=True, profiles=[self.profile]
        )
        self.after_import()
        return response

    def CreateProvider(self, request, **_):
        self._capture("create", request)
        if self.fail_create:
            raise _RpcFailure(grpc.StatusCode.DEADLINE_EXCEEDED)
        if self.provider is not None:
            raise _RpcFailure(grpc.StatusCode.ALREADY_EXISTS)
        self.provider = datamodel_pb2.Provider()
        self.provider.CopyFrom(request.provider)
        self.provider.metadata.id = "actual-gateway-created-id"
        self.provider.metadata.resource_version = 1
        self.writes += 1
        self.after_create()
        return openshell_pb2.ProviderResponse(provider=self.provider)

    def GetProvider(self, request, **_):
        self._capture("get", request)
        if self.provider is None:
            raise _RpcFailure(grpc.StatusCode.NOT_FOUND)
        return openshell_pb2.ProviderResponse(provider=self.provider)

    def _guard(self, request):
        assert request.provider == self.provider.metadata.name
        if request.expected_resource_version != self.provider.metadata.resource_version:
            raise _RpcFailure(grpc.StatusCode.ABORTED)

    def ConfigureProviderRefresh(self, request, **_):
        self._capture("configure", request)
        self._guard(request)
        self.writes += 1
        self.provider.metadata.resource_version += 1
        self.after_refresh()
        return openshell_pb2.ConfigureProviderRefreshResponse()

    def RotateProviderCredential(self, request, **_):
        self._capture("rotate", request)
        if self.replace_during_rotate:
            self.provider.metadata.resource_version += 5
        self._guard(request)
        self.writes += 1
        self.provider.metadata.resource_version += 1
        self.after_refresh()
        return openshell_pb2.RotateProviderCredentialResponse()

    def GetProviderRefreshStatus(self, request, **_):
        self._capture("status", request)
        return openshell_pb2.GetProviderRefreshStatusResponse(
            credentials=[
                openshell_pb2.ProviderCredentialRefreshStatus(
                    provider=self.provider.metadata.name,
                    provider_id=self.provider.metadata.id,
                    credential_key="AWS_ACCESS_KEY_ID",
                    strategy=openshell_pb2.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE,
                    status="refreshed",
                    last_error="MUST_NOT_EXPORT_PRIVATE_PROVIDER_PROSE",
                )
            ]
        )


class ProviderBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.profile = _profile()
        self.stub = _Stub(self.profile)
        self.owned = {}
        self.revoked = False
        self.clients = []

        def client(endpoint, **kwargs):
            self.clients.append((endpoint, kwargs))
            return SimpleNamespace(_stub=self.stub, close=lambda: None)

        self.patch = patch(
            "openshell.provider_bootstrap.SandboxClient", side_effect=client
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def _require_current(self):
        if self.revoked:
            raise ValueError("private installation details")

    def _record(self, ownership):
        self.owned[ownership.provider_id] = ownership

    def _require_owned(self, ownership):
        if self.owned.get(ownership.provider_id) != ownership:
            raise ValueError("not a genuine retained Create acknowledgement")

    def make(self, **overrides):
        args = {
            "tls": TlsConfig(Path("ca.pem"), Path("client.pem"), Path("key.pem")),
            "installation_id": "owned-installation",
            "workspace": "default",
            "profile": self.profile,
            "expected_profile_sha256": profile_sha256(self.profile),
            "require_installation_current": self._require_current,
            "record_created": self._record,
            "require_owned": self._require_owned,
        }
        args.update(overrides)
        return ProviderBootstrap("https://gateway.example:8080", **args)

    def test_secure_constructor_and_fixed_profile(self):
        with self.assertRaises(ProviderBootstrapError):
            self.make(tls=TlsConfig(Path("ca.pem")))
        changed = _profile()
        changed.discovery.credentials.append("access_key_id")
        with self.assertRaises(ProviderBootstrapError):
            self.make(profile=changed, expected_profile_sha256=profile_sha256(changed))
        self.assertEqual(self.clients, [])
        self.make()
        self.assertEqual(self.clients[0][0], "gateway.example:8080")
        self.assertIsInstance(self.clients[0][1]["tls"], TlsConfig)

    def test_old_server_refuses_before_import_create_or_secret_resolution(self):
        self.stub.support = False
        bootstrap = self.make()
        with self.assertRaises(ProviderBootstrapError) as caught:
            bootstrap.install("signer", import_profile=True)
        self.assertEqual(
            caught.exception.code, "resource_version_preconditions_unsupported"
        )
        self.assertEqual([name for name, _ in self.stub.calls], ["support"])
        self.assertEqual(self.stub.writes, 0)

    def test_explicit_install_guarded_configure_rotate_and_status(self):
        bootstrap = self.make()
        ownership = bootstrap.install("signer", import_profile=True)
        self.assertEqual(ownership.provider_id, "actual-gateway-created-id")
        self.assertEqual(ownership.resource_version, 1)
        self.assertEqual(bootstrap.install("signer", ownership=ownership), ownership)
        observation = bootstrap.configure(
            ownership,
            GatewayDefaultChainSource(
                "arn:aws:iam::123456789012:role/signer", "us-east-1"
            ),
        )
        self.assertEqual(observation.resource_version, 2)
        configured = next(
            request for name, request in self.stub.calls if name == "configure"
        )
        self.assertEqual(configured.provider, ownership.name)
        self.assertEqual(configured.expected_resource_version, 1)
        self.assertNotIn("aws_access_key_id", configured.material)
        self.assertEqual(bootstrap.rotate(ownership).resource_version, 3)
        rotated = next(request for name, request in self.stub.calls if name == "rotate")
        self.assertEqual(rotated.expected_resource_version, 2)
        status = bootstrap.refresh_status(ownership)
        self.assertEqual(status.status, "refreshed")
        self.assertNotIn("PRIVATE_PROVIDER", repr(status))
        self.assertEqual(sum(name == "create" for name, _ in self.stub.calls), 1)

    def test_missing_replaced_foreign_or_changed_config_never_recreated(self):
        for scenario in ("missing", "replaced", "config", "foreign", "revoked"):
            with self.subTest(scenario=scenario):
                self.stub = _Stub(self.profile)
                bootstrap = self.make()
                ownership = bootstrap.install("signer")
                writes = self.stub.writes
                if scenario == "missing":
                    self.stub.provider = None
                elif scenario == "replaced":
                    self.stub.provider.metadata.id = "replacement"
                elif scenario == "config":
                    self.stub.provider.config["new"] = "different"
                elif scenario == "foreign":
                    ownership = replace(ownership, installation_id="foreign")
                else:
                    self.revoked = True
                with self.assertRaises(ProviderBootstrapError):
                    bootstrap.rotate(ownership)
                self.assertEqual(self.stub.writes, writes)
                self.assertEqual(
                    sum(name == "create" for name, _ in self.stub.calls), 1
                )
                self.revoked = False

    def test_ambiguous_create_is_not_retried_or_adopted(self):
        bootstrap = self.make()
        self.stub.fail_create = True
        with self.assertRaises(ProviderBootstrapError) as caught:
            bootstrap.install("signer")
        receipt = caught.exception.receipt
        self.assertEqual(receipt.effects, "unknown")
        self.assertEqual(receipt.grpc_status, 4)
        self.assertTrue(receipt.request_id)
        with self.assertRaises(ProviderBootstrapError) as again:
            bootstrap.install("signer")
        self.assertEqual(again.exception.code, "unsettled_mutation")
        self.assertEqual(sum(name == "create" for name, _ in self.stub.calls), 1)
        self.assertEqual(self.owned, {})

    def test_create_ack_after_revocation_preserves_exact_cleanup_evidence(self):
        bootstrap = self.make()
        self.stub.after_create = lambda: setattr(self, "revoked", True)
        with self.assertRaises(ProviderBootstrapError) as caught:
            bootstrap.install("signer")
        receipt = caught.exception.receipt
        self.assertEqual(receipt.effects, "applied")
        self.assertEqual(receipt.provider_id, "actual-gateway-created-id")
        self.assertEqual(receipt.provider_name, "signer")
        self.assertEqual(receipt.resource_version, 1)
        self.assertEqual(self.owned, {})
        self.revoked = False
        with self.assertRaises(ProviderBootstrapError) as again:
            bootstrap.install("signer")
        self.assertEqual(again.exception.code, "unsettled_mutation")
        self.assertEqual(sum(name == "create" for name, _ in self.stub.calls), 1)

    def test_late_provider_change_aborted_is_unknown(self):
        bootstrap = self.make()
        ownership = bootstrap.install("signer")
        self.stub.replace_during_rotate = True
        writes = self.stub.writes
        with self.assertRaises(ProviderBootstrapError) as caught:
            bootstrap.rotate(ownership)
        self.assertEqual(caught.exception.receipt.effects, "unknown")
        self.assertEqual(caught.exception.receipt.grpc_status, 10)
        self.assertEqual(self.stub.writes, writes)
        self.assertEqual(sum(name == "rotate" for name, _ in self.stub.calls), 1)

    def test_post_ack_read_failure_retains_applied_effects_and_blocks_mutation(self):
        for method in ("configure", "rotate"):
            with self.subTest(method=method):
                self.stub = _Stub(self.profile)
                bootstrap = self.make()
                ownership = bootstrap.install("signer")
                self.stub.after_refresh = lambda: self.stub.provider.config.update(
                    {"changed-after-ack": "different"}
                )
                with self.assertRaises(ProviderBootstrapError) as caught:
                    if method == "configure":
                        bootstrap.configure(
                            ownership,
                            GatewayDefaultChainSource(
                                "arn:aws:iam::123456789012:role/signer", "us-east-1"
                            ),
                        )
                    else:
                        bootstrap.rotate(ownership)
                receipt = caught.exception.receipt
                sent = next(
                    request for name, request in self.stub.calls if name == method
                )
                self.assertEqual(
                    caught.exception.code, "post_mutation_verification_unsettled"
                )
                self.assertEqual(receipt.effects, "applied")
                self.assertEqual(receipt.request_id, sent.request_id)
                self.assertEqual(receipt.provider_id, ownership.provider_id)
                writes = self.stub.writes
                self.stub.provider.config.clear()
                with self.assertRaises(ProviderBootstrapError) as again:
                    bootstrap.rotate(ownership)
                self.assertEqual(again.exception.receipt, receipt)
                self.assertEqual(self.stub.writes, writes)

        self.stub = _Stub(self.profile)

        def record_then_drift(ownership):
            self._record(ownership)
            self.stub.provider.config["changed-after-ack"] = "different"

        bootstrap = self.make(record_created=record_then_drift)
        with self.assertRaises(ProviderBootstrapError) as created:
            bootstrap.install("signer")
        receipt = created.exception.receipt
        self.assertEqual(created.exception.code, "post_mutation_verification_unsettled")
        self.assertEqual(receipt.effects, "applied")
        self.assertEqual(receipt.provider_id, "actual-gateway-created-id")
        self.assertEqual(receipt.resource_version, 1)
        self.stub.provider.config.clear()
        with self.assertRaises(ProviderBootstrapError) as repeated:
            bootstrap.install("signer")
        self.assertEqual(repeated.exception.receipt, receipt)
        self.assertEqual(self.stub.writes, 1)

        self.stub = _Stub(self.profile)
        self.stub.after_import = lambda: setattr(
            self.stub.profile, "description", "drift"
        )
        bootstrap = self.make()
        with self.assertRaises(ProviderBootstrapError) as imported:
            bootstrap.install("signer", import_profile=True)
        receipt = imported.exception.receipt
        self.assertEqual(receipt.operation, "ImportProviderProfiles")
        self.assertEqual(receipt.effects, "applied")
        self.assertTrue(receipt.request_id)
        self.assertFalse(any(name == "create" for name, _ in self.stub.calls))
        self.stub.profile.description = ""
        with self.assertRaises(ProviderBootstrapError) as repeated:
            bootstrap.install("signer", import_profile=True)
        self.assertEqual(repeated.exception.receipt, receipt)
        self.assertEqual(self.stub.writes, 1)

        self.stub = _Stub(self.profile)
        self.stub.fail_create = True
        bootstrap = self.make()
        with self.assertRaises(ProviderBootstrapError) as later:
            bootstrap.install("signer", import_profile=True)
        self.assertEqual(later.exception.receipt.operation, "CreateProvider")
        self.assertEqual(later.exception.receipt.effects, "unknown")

    def test_secret_reference_is_explicit_partial_credentials_refuse(self):
        bootstrap = self.make()
        ownership = bootstrap.install("signer")
        reference = object()
        calls = []

        def resolve(actual):
            self.assertIs(actual, reference)
            calls.append(actual)
            return SimpleNamespace(
                access_key="EXPLICIT_TEST_ACCESS", secret_key="", token="orphan"
            )

        source = SecretRefreshSource(
            "arn:aws:iam::123456789012:role/signer", "us-east-1", reference, resolve
        )
        with self.assertRaises(ProviderBootstrapError) as caught:
            bootstrap.configure(ownership, source)
        self.assertEqual(caught.exception.code, "credential_source_incomplete")
        self.assertEqual(len(calls), 1)
        self.assertFalse(any(name == "configure" for name, _ in self.stub.calls))
        self.assertNotIn("EXPLICIT_TEST_ACCESS", repr(source))

    def test_complete_secret_source_is_transient_and_old_support_never_resolves(self):
        bootstrap = self.make()
        ownership = bootstrap.install("signer")
        calls = []

        def resolve(reference):
            calls.append(reference)
            return SimpleNamespace(
                access_key="CONTROLLED_ACCESS",
                secret_key="CONTROLLED_SECRET",
                token="CONTROLLED_TOKEN",
            )

        source = SecretRefreshSource(
            "arn:aws:iam::123456789012:role/signer", "us-east-1", object(), resolve
        )
        self.stub.support = False
        with self.assertRaises(ProviderBootstrapError):
            bootstrap.configure(ownership, source)
        self.assertEqual(calls, [])
        self.stub.support = True
        observation = bootstrap.configure(ownership, source)
        sent = next(request for name, request in self.stub.calls if name == "configure")
        self.assertEqual(sent.material["aws_secret_access_key"], "CONTROLLED_SECRET")
        self.assertEqual(
            set(sent.secret_material_keys),
            {"aws_secret_access_key", "aws_session_token"},
        )
        self.assertNotIn("CONTROLLED_SECRET", repr(observation))
        self.assertNotIn("CONTROLLED_TOKEN", repr(source))

    def test_bound_failure_details_proves_preflight_or_typed_refusal_none(self):
        for case in ("missing-profile", "local-input", "typed-import-refused"):
            with self.subTest(case=case):
                self.stub = _Stub(self.profile)
                bootstrap = self.make()
                attempt_id = str(uuid.uuid4())
                if case == "missing-profile":
                    self.stub.GetProviderProfile = lambda *_args, **_kw: (
                        _ for _ in ()
                    ).throw(_RpcFailure(grpc.StatusCode.NOT_FOUND))
                if case == "typed-import-refused":
                    self.stub.ImportProviderProfiles = lambda *_args, **_kw: (
                        openshell_pb2.ImportProviderProfilesResponse(imported=False)
                    )
                with self.assertRaises(ProviderBootstrapError) as caught:
                    bootstrap.install(
                        "" if case == "local-input" else "signer",
                        import_profile=case == "typed-import-refused",
                        attempt_id=attempt_id,
                    )
                details = bootstrap.failure_details(
                    caught.exception, operation="install", attempt_id=attempt_id
                )
                self.assertIsNotNone(details)
                self.assertEqual(details.effects, "none")
                self.assertEqual(details.attempt_id, attempt_id)
                self.assertEqual(self.stub.writes, 0)
                self.assertFalse(any(name == "create" for name, _ in self.stub.calls))
                self.assertEqual(
                    len(details.mutations), int(case == "typed-import-refused")
                )

        self.stub = _Stub(self.profile)
        bootstrap = self.make()
        self.stub.ImportProviderProfiles = lambda *_args, **_kwargs: SimpleNamespace(
            imported=False
        )
        attempt_id = str(uuid.uuid4())
        with self.assertRaises(ProviderBootstrapError) as untyped:
            bootstrap.install("signer", import_profile=True, attempt_id=attempt_id)
        details = bootstrap.failure_details(
            untyped.exception, operation="install", attempt_id=attempt_id
        )
        self.assertEqual(details.effects, "unknown")
        self.assertEqual(details.code, "invalid_mutation_ack")

    def test_bound_failure_details_keeps_unknown_and_earlier_import_effects(self):
        bootstrap = self.make()
        self.stub.fail_create = True
        attempt_id = str(uuid.uuid4())
        with self.assertRaises(ProviderBootstrapError) as lost:
            bootstrap.install("signer", attempt_id=attempt_id)
        details = bootstrap.failure_details(
            lost.exception, operation="install", attempt_id=attempt_id
        )
        self.assertEqual(details.effects, "unknown")
        self.assertEqual(details.mutations[0].operation, "CreateProvider")
        # Public receipt modification cannot downgrade the private unsettled
        # history carried into a later operation that itself sends no mutation.
        object.__setattr__(lost.exception.receipt, "effects", "none")
        next_id = str(uuid.uuid4())
        with self.assertRaises(ProviderBootstrapError) as later:
            bootstrap.install("signer", attempt_id=next_id)
        later_details = bootstrap.failure_details(
            later.exception, operation="install", attempt_id=next_id
        )
        self.assertEqual(later_details.effects, "unknown")
        self.assertEqual(sum(name == "create" for name, _ in self.stub.calls), 1)

        for case in ("read-failure", "revoked-after-read"):
            with self.subTest(case=case):
                self.stub = _Stub(self.profile)
                self.revoked = False
                bootstrap = self.make()
                if case == "read-failure":

                    def after_import():
                        def missing_profile(*_args, **_kwargs):
                            raise _RpcFailure(grpc.StatusCode.NOT_FOUND)

                        self.stub.GetProviderProfile = missing_profile

                    self.stub.after_import = after_import
                else:
                    original_read = bootstrap._remote_profile

                    def revoke_after_validated_read(read=original_read):
                        read()
                        self.revoked = True

                    bootstrap._remote_profile = revoke_after_validated_read
                attempt_id = str(uuid.uuid4())
                with self.assertRaises(ProviderBootstrapError) as caught:
                    bootstrap.install(
                        "signer", import_profile=True, attempt_id=attempt_id
                    )
                details = bootstrap.failure_details(
                    caught.exception, operation="install", attempt_id=attempt_id
                )
                self.assertEqual(details.effects, "applied")
                self.assertEqual(
                    [row.operation for row in details.mutations],
                    ["ImportProviderProfiles"],
                )
                self.assertEqual(self.stub.writes, 1)
                self.assertFalse(any(name == "create" for name, _ in self.stub.calls))
                self.revoked = False

    def test_bound_failure_details_keeps_all_post_ack_effects_applied(self):
        for operation in ("install", "configure", "rotate"):
            with self.subTest(operation=operation):
                self.stub = _Stub(self.profile)
                bootstrap = self.make()
                if operation == "install":
                    self.stub.after_create = lambda: self.stub.provider.config.update(
                        {"drift": "yes"}
                    )
                else:
                    ownership = bootstrap.install("signer")
                    self.stub.after_refresh = lambda: self.stub.provider.config.update(
                        {"drift": "yes"}
                    )
                attempt_id = str(uuid.uuid4())
                with self.assertRaises(ProviderBootstrapError) as caught:
                    if operation == "install":
                        bootstrap.install("signer", attempt_id=attempt_id)
                    elif operation == "configure":
                        bootstrap.configure(
                            ownership,
                            GatewayDefaultChainSource(
                                "arn:aws:iam::123456789012:role/signer", "us-east-1"
                            ),
                            attempt_id=attempt_id,
                        )
                    else:
                        bootstrap.rotate(ownership, attempt_id=attempt_id)
                details = bootstrap.failure_details(
                    caught.exception, operation=operation, attempt_id=attempt_id
                )
                self.assertEqual(details.effects, "applied")
                self.assertEqual(len(details.mutations), 1)

    def test_failure_details_rejects_foreign_tampered_or_mismatched_proof(self):
        bootstrap = self.make()
        attempt_id = str(uuid.uuid4())
        with self.assertRaises(ProviderBootstrapError) as caught:
            bootstrap.install("", attempt_id=attempt_id)
        error = caught.exception
        details = bootstrap.failure_details(
            error, operation="install", attempt_id=attempt_id
        )
        self.assertEqual(details.effects, "none")
        foreign = ProviderBootstrapError(error.code, error.receipt)
        subclass = type("ForeignSubclass", (ProviderBootstrapError,), {})(error.code)
        other = self.make()
        for helper, candidate, operation, attempt in (
            (bootstrap, foreign, "install", attempt_id),
            (bootstrap, subclass, "install", attempt_id),
            (bootstrap, RuntimeError(), "install", attempt_id),
            (other, error, "install", attempt_id),
            (bootstrap, error, "rotate", attempt_id),
            (bootstrap, error, "install", str(uuid.uuid4())),
        ):
            self.assertIsNone(
                helper.failure_details(
                    candidate, operation=operation, attempt_id=attempt
                )
            )
        for field, value in (
            ("effects", "applied"),
            ("effects", {}),
            ("code", "different_code"),
            (
                "receipt",
                BootstrapOperationReceipt("CreateProvider", str(uuid.uuid4()), "none"),
            ),
        ):
            original = getattr(error, field)
            setattr(error, field, value)
            self.assertIsNone(
                bootstrap.failure_details(
                    error, operation="install", attempt_id=attempt_id
                )
            )
            setattr(error, field, original)
        self.assertEqual(
            bootstrap.failure_details(
                error, operation="install", attempt_id=attempt_id
            ),
            details,
        )
        with self.assertRaises(ProviderBootstrapError) as unbound:
            bootstrap.install("")
        self.assertIsNone(
            bootstrap.failure_details(
                unbound.exception, operation="install", attempt_id=attempt_id
            )
        )
        self.assertIsNone(
            bootstrap.failure_details(error, operation="install", attempt_id=attempt_id)
        )

    def test_bound_attempt_serializes_unbound_mutations_and_busy_has_no_proof(self):
        bootstrap = self.make()
        entered, release = threading.Event(), threading.Event()
        errors = []

        def missing_profile(*_args, **_kwargs):
            entered.set()
            if not release.wait(2):
                raise AssertionError("bounded mock waiter expired")
            raise _RpcFailure(grpc.StatusCode.NOT_FOUND)

        self.stub.GetProviderProfile = missing_profile
        attempt_id = str(uuid.uuid4())

        def install():
            try:
                bootstrap.install("signer", attempt_id=attempt_id)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=install)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            with self.assertRaises(ProviderBootstrapError) as busy:
                bootstrap.install("unbound-other")
            self.assertEqual(busy.exception.code, "bootstrap_busy")
            self.assertIsNone(
                bootstrap.failure_details(
                    busy.exception, operation="install", attempt_id=attempt_id
                )
            )
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertEqual(
            bootstrap.failure_details(
                errors[0], operation="install", attempt_id=attempt_id
            ).effects,
            "none",
        )
        self.assertEqual(self.stub.writes, 0)


if __name__ == "__main__":
    unittest.main()
