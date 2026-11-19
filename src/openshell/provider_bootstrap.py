# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Explicit installation-owned bootstrap for an endpointless Bedrock signer.

This is an operator/admin API, not Agent admission. The caller supplies a
reviewed profile pin and trusted installation callbacks. Ownership receipts
are evidence from an acknowledged Create; they are not bearer credentials.
Read and refresh methods never create, import, replace, or delete resources.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeVar, cast
from urllib.parse import urlsplit

import grpc

from ._proto import datamodel_pb2, openshell_pb2
from .sandbox import SandboxClient, TlsConfig

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from .sandbox import ClientCredentialsAuth

_PROFILE_ID = "aws-bedrock-signing"
_CREDENTIAL = "AWS_ACCESS_KEY_ID"
_STRATEGY = openshell_pb2.PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE
_MATERIAL = {
    "role_arn": (True, False),
    "session_name": (False, False),
    "external_id": (False, False),
    "aws_region": (False, False),
    "aws_access_key_id": (False, False),
    "aws_secret_access_key": (False, True),
    "aws_session_token": (False, True),
}
_Result = TypeVar("_Result")
_ReceiptSnapshot = tuple[str, str, str, int | None, str, str, int]


@dataclass(frozen=True)
class BootstrapOperationReceipt:
    """Nonsecret operation outcome; unknown effects never authorize a retry."""

    operation: str
    request_id: str
    effects: Literal["none", "applied", "unknown"]
    grpc_status: int | None = None
    provider_id: str = ""
    provider_name: str = ""
    resource_version: int = 0


@dataclass(frozen=True)
class BootstrapFailureDetails:
    """Source-issued failure for one exact helper operation and caller attempt.

    Only ``ProviderBootstrap.failure_details`` establishes its provenance.
    The mutation history covers the whole operation, not just its last error.
    """

    attempt_id: str
    operation: Literal["install", "configure", "rotate"]
    code: str
    effects: Literal["none", "applied", "unknown"]
    mutations: tuple[BootstrapOperationReceipt, ...]


class ProviderBootstrapError(RuntimeError):
    """Closed failure code and optional nonsecret mutation receipt."""

    def __init__(
        self, code: str, receipt: BootstrapOperationReceipt | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.receipt = receipt
        self.effects = receipt.effects if receipt is not None else "none"


def _receipt_snapshot(receipt: object) -> _ReceiptSnapshot | None:
    """Detach only the fixed nonsecret scalar contract, never exception prose."""
    if type(receipt) is not BootstrapOperationReceipt:
        return None
    fields = vars(receipt).copy()
    if set(fields) != {
        "operation",
        "request_id",
        "effects",
        "grpc_status",
        "provider_id",
        "provider_name",
        "resource_version",
    }:
        return None
    for name, bound in (
        ("operation", 64),
        ("request_id", 64),
        ("provider_id", 256),
        ("provider_name", 256),
    ):
        value = fields[name]
        if (
            type(value) is not str
            or len(value) > bound
            or any(ord(char) < 32 for char in value)
        ):
            return None
    if (
        type(fields["effects"]) is not str
        or fields["operation"]
        not in {
            "ListProviderProfiles",
            "GetProviderProfile",
            "GetProvider",
            "ImportProviderProfiles",
            "CreateProvider",
            "ConfigureProviderRefresh",
            "RotateProviderCredential",
            "GetProviderRefreshStatus",
        }
        or fields["effects"] not in {"none", "applied", "unknown"}
    ):
        return None
    status = fields["grpc_status"]
    if status is not None and (type(status) is not int or not 0 <= status <= 16):
        return None
    version = fields["resource_version"]
    if type(version) is not int or not 0 <= version < 1 << 64:
        return None
    return (
        fields["operation"],
        fields["request_id"],
        fields["effects"],
        status,
        fields["provider_id"],
        fields["provider_name"],
        version,
    )


def _error_snapshot(error: BaseException) -> tuple | None:
    if type(error) is not ProviderBootstrapError:
        return None
    fields = vars(error).copy()
    code, effects, receipt = (
        fields.get(name) for name in ("code", "effects", "receipt")
    )
    if (
        type(code) is not str
        or not 0 < len(code) <= 80
        or not code.isascii()
        or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in code)
        or type(effects) is not str
        or effects not in {"none", "applied", "unknown"}
    ):
        return None
    snapshot = None if receipt is None else _receipt_snapshot(receipt)
    if receipt is not None and snapshot is None:
        return None
    return code, effects, snapshot


@dataclass(frozen=True)
class ProviderOwnership:
    """Create acknowledgement persisted by the trusted installation owner.

    Constructing this value alone establishes no ownership. ``require_owned``
    must verify it against the installer's protected Create-acknowledgement
    record. ``resource_version`` is the original Create version, not a lease
    on future versions produced by normal gateway refresh.
    """

    installation_id: str
    gateway_url: str
    workspace: str
    name: str
    provider_id: str
    resource_version: int
    profile_sha256: str
    config_sha256: str
    create_request_id: str


@dataclass(frozen=True)
class ProviderObservation:
    """Current nonsecret identity, never an Agent/Run availability grant."""

    ownership: ProviderOwnership
    resource_version: int


@dataclass(frozen=True)
class ProviderRefreshObservation:
    """Nonsecret status from one unchanged Provider observation."""

    provider: ProviderObservation
    status: str
    expiration_time: tuple[int, int] | None
    next_refresh_time: tuple[int, int] | None


class _FrozenAwsCredentials(Protocol):
    access_key: str
    secret_key: str
    token: str | None


@dataclass(frozen=True)
class GatewayDefaultChainSource:
    """Explicitly select the gateway installation's AWS credential chain.

    The Python SDK performs no credential discovery. The existing gateway STS
    strategy resolves its own declared installation identity when it mints.
    """

    role_arn: str
    aws_region: str
    session_name: str = ""
    external_id: str = ""


@dataclass(frozen=True)
class SecretRefreshSource:
    """Adapt an existing trusted credential reference/resolver, without parsing.

    For example, an installation can bind its existing ``CredentialRef`` and
    a resolver returning ``ResolvedCredential.aws_credentials`` frozen via
    ``get_frozen_credentials()``. No new reference syntax or secret DTO is
    introduced. The callback is invoked only by explicit ``configure``.
    """

    role_arn: str
    aws_region: str
    reference: object = field(repr=False)
    resolve: Callable[[object], _FrozenAwsCredentials] = field(repr=False)
    session_name: str = ""
    external_id: str = ""


def _text(value: str, *, maximum: int = 1024) -> str:
    if (
        type(value) is not str
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ProviderBootstrapError("invalid_input")
    return value


def _profile_bytes(profile: openshell_pb2.ProviderProfile) -> bytes:
    copy = openshell_pb2.ProviderProfile()
    copy.CopyFrom(profile)
    for name in ("resource_version", "source", "scope"):
        copy.ClearField(name)
    return copy.SerializeToString(deterministic=True)


def profile_sha256(profile: openshell_pb2.ProviderProfile) -> str:
    """Hash semantic protobuf bytes, excluding server-owned provenance fields."""
    if type(profile) is not openshell_pb2.ProviderProfile:
        raise ProviderBootstrapError("invalid_profile")
    return hashlib.sha256(_profile_bytes(profile)).hexdigest()


def _check_profile(profile: openshell_pb2.ProviderProfile, expected: str) -> None:
    if (
        profile_sha256(profile) != expected
        or profile.id != _PROFILE_ID
        or profile.category != openshell_pb2.PROVIDER_PROFILE_CATEGORY_INFERENCE
        or not profile.inference_capable
        or profile.endpoints
        or profile.binaries
        or profile.discovery.credentials
        or {item.name for item in profile.credentials}
        != {"access_key_id", "secret_access_key", "session_token"}
        or len(profile.credentials) != 3
    ):
        raise ProviderBootstrapError("profile_mismatch")
    credentials = {item.name: item for item in profile.credentials}
    for name, env in (
        ("access_key_id", "AWS_ACCESS_KEY_ID"),
        ("secret_access_key", "AWS_SECRET_ACCESS_KEY"),
        ("session_token", "AWS_SESSION_TOKEN"),
    ):
        item = credentials[name]
        if (
            not item.required
            or list(item.env_vars) != [env]
            or item.auth_style
            or item.header_name
            or item.query_param
            or item.path_template
            or item.HasField("token_grant")
            or (name != "access_key_id" and item.HasField("refresh"))
        ):
            raise ProviderBootstrapError("profile_mismatch")
    refresh = credentials["access_key_id"].refresh
    if (
        refresh.strategy != _STRATEGY
        or refresh.token_url
        or refresh.scopes
        or refresh.refresh_before.seconds != 300
        or refresh.refresh_before.nanos
        or refresh.max_lifetime.seconds != 3600
        or refresh.max_lifetime.nanos
        or len(refresh.material) != len(_MATERIAL)
        or {item.name: (item.required, item.secret) for item in refresh.material}
        != _MATERIAL
        or len(refresh.additional_outputs) != 2
        or {(item.output, item.credential) for item in refresh.additional_outputs}
        != {
            ("secret_access_key", "secret_access_key"),
            ("session_token", "session_token"),
        }
    ):
        raise ProviderBootstrapError("profile_mismatch")


def _config_hash(config: Mapping[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(dict(config), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class ProviderBootstrap:
    """Strict-mTLS admin bootstrap using the existing OpenShell RPC service.

    All callbacks are constructor-selected trusted installer code. The
    ``require_*`` callbacks return None or raise; ``record_created`` durably
    persists the actual Create acknowledgement before subsequent use. Neither
    annotations nor this module's receipt values replace those checks.
    """

    def __init__(
        self,
        gateway_url: str,
        *,
        tls: TlsConfig,
        installation_id: str,
        workspace: str,
        profile: openshell_pb2.ProviderProfile,
        expected_profile_sha256: str,
        require_installation_current: Callable[[], None],
        record_created: Callable[[ProviderOwnership], None],
        require_owned: Callable[[ProviderOwnership], None],
        bearer_token: str | Callable[[], str] | None = None,
        client_credentials: ClientCredentialsAuth | None = None,
        timeout: float = 30.0,
    ) -> None:
        parsed = None
        try:
            parsed = urlsplit(gateway_url)
            # Validate port syntax before handing the authority to gRPC.
            if parsed.port is not None and not 0 < parsed.port <= 65535:
                parsed = None
        except (TypeError, ValueError):
            parsed = None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or type(tls) is not TlsConfig
            or not all((tls.ca_path, tls.cert_path, tls.key_path))
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 120
        ):
            raise ProviderBootstrapError("strict_mtls_required")
        if (
            type(expected_profile_sha256) is not str
            or len(expected_profile_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_profile_sha256)
        ):
            raise ProviderBootstrapError("invalid_profile_pin")
        _check_profile(profile, expected_profile_sha256)
        self._profile = openshell_pb2.ProviderProfile.FromString(
            _profile_bytes(profile)
        )
        self._profile_pin = expected_profile_sha256
        self._installation = _text(installation_id, maximum=256)
        self._workspace = _text(workspace, maximum=256)
        self._gateway = gateway_url.rstrip("/")
        self._require_current = require_installation_current
        self._record_created = record_created
        self._require_owned = require_owned
        self._timeout = timeout
        self._unknown: BootstrapOperationReceipt | None = None
        self._unsettled_snapshot: _ReceiptSnapshot | None = None
        self._attempt_lock = threading.Lock()
        self._attempt_mutations: list[_ReceiptSnapshot] | None = None
        self._failure_record: tuple | None = None
        self._closed = False
        self._check_current()
        authority = parsed.netloc
        self._client = SandboxClient(
            authority,
            tls=tls,
            bearer_token=bearer_token,
            client_credentials=client_credentials,
            timeout=timeout,
        )

    def close(self) -> None:
        self._closed = True
        self._client.close()

    def _check_current(self) -> None:
        if self._closed:
            raise ProviderBootstrapError("closed")
        failed = False
        try:
            failed = self._require_current() is not None
        except Exception:
            failed = True
        if failed:
            raise ProviderBootstrapError("installation_not_current")

    def _scope(self) -> datamodel_pb2.WorkspaceSelector:
        return datamodel_pb2.WorkspaceSelector(workspace=self._workspace)

    def _run_attempt(
        self, operation: str, attempt_id: str | None, call: Callable[[], _Result]
    ) -> _Result:
        if attempt_id is not None:
            try:
                valid = (
                    type(attempt_id) is str
                    and str(uuid.UUID(attempt_id)) == attempt_id
                    and uuid.UUID(attempt_id).int != 0
                )
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise ProviderBootstrapError("invalid_attempt_id")
        if not self._attempt_lock.acquire(blocking=False):
            raise ProviderBootstrapError("bootstrap_busy")
        mutations = (
            [self._unsettled_snapshot] if self._unsettled_snapshot is not None else []
        )
        self._attempt_mutations = mutations
        self._failure_record = None
        try:
            return call()
        except BaseException as error:
            public = _error_snapshot(error)
            if attempt_id is not None and public is not None:
                self._failure_record = (
                    error,
                    operation,
                    attempt_id,
                    public,
                    tuple(mutations),
                )
            raise
        finally:
            self._attempt_mutations = None
            self._attempt_lock.release()

    def failure_details(
        self, error: BaseException, *, operation: str, attempt_id: str
    ) -> BootstrapFailureDetails | None:
        """Return exact source provenance, or None; never trust public effects.

        A caller records its canonical nonzero attempt UUID durably before
        invoking a mutation method with that UUID. Only this helper's retained
        terminal error for that same operation/attempt qualifies. Foreign,
        subclassed, mutated, busy, unbound, and evicted errors do not qualify.
        A missing result leaves the caller's pending outcome unresolved.
        """
        if (
            type(self) is not ProviderBootstrap
            or type(error) is not ProviderBootstrapError
        ):
            return None
        if not self._attempt_lock.acquire(blocking=False):
            return None
        try:
            record = self._failure_record
            if (
                record is None
                or record[0] is not error
                or type(operation) is not str
                or type(attempt_id) is not str
                or record[1] != operation
                or record[2] != attempt_id
                or _error_snapshot(error) != record[3]
            ):
                return None
            mutations = record[4]
            effects = (
                "unknown"
                if any(row[2] == "unknown" for row in mutations)
                else "applied"
                if any(row[2] == "applied" for row in mutations)
                else "none"
            )
            return BootstrapFailureDetails(
                attempt_id,
                cast("Literal['install', 'configure', 'rotate']", operation),
                record[3][0],
                effects,
                tuple(BootstrapOperationReceipt(*row) for row in mutations),
            )
        finally:
            self._attempt_lock.release()

    def _set_unsettled(self, receipt: BootstrapOperationReceipt) -> _ReceiptSnapshot:
        snapshot = _receipt_snapshot(receipt)
        if snapshot is None:
            raise ProviderBootstrapError("invalid_internal_receipt")
        self._unknown = receipt
        self._unsettled_snapshot = snapshot
        return snapshot

    def _unsettled_receipt(self) -> BootstrapOperationReceipt:
        if self._unsettled_snapshot is None:
            raise ProviderBootstrapError("invalid_internal_receipt")
        return BootstrapOperationReceipt(*cast("Any", self._unsettled_snapshot))

    def _record_mutation(
        self, receipt: BootstrapOperationReceipt, index: int | None
    ) -> None:
        if index is not None and self._attempt_mutations is not None:
            snapshot = _receipt_snapshot(receipt)
            if snapshot is None:
                raise ProviderBootstrapError("invalid_internal_receipt")
            self._attempt_mutations[index] = snapshot

    def _rpc(self, method: str, request: Any, *, mutation: bool = False):
        self._check_current()
        if mutation and self._unknown is not None:
            raise ProviderBootstrapError(
                "unsettled_mutation", self._unsettled_receipt()
            )
        mutation_index = None
        if mutation:
            pending = BootstrapOperationReceipt(method, request.request_id, "unknown")
            snapshot = self._set_unsettled(pending)  # Before send, including lost ACK.
            if self._attempt_mutations is not None:
                mutation_index = len(self._attempt_mutations)
                self._attempt_mutations.append(snapshot)
        failure: BootstrapOperationReceipt | None = None
        status = None
        try:
            result = getattr(self._client._stub, method)(request, timeout=self._timeout)
        except Exception as error:
            if isinstance(error, grpc.RpcError):
                code = error.code()
                if isinstance(code, grpc.StatusCode):
                    status = code.value[0]
            failure = BootstrapOperationReceipt(
                method,
                getattr(request, "request_id", ""),
                "unknown" if mutation else "none",
                status,
            )
        if failure is not None:
            if mutation:
                self._set_unsettled(failure)
                self._record_mutation(failure, mutation_index)
            raise ProviderBootstrapError("rpc_failed", failure)
        if mutation:
            response_type = {
                "ImportProviderProfiles": openshell_pb2.ImportProviderProfilesResponse,
                "CreateProvider": openshell_pb2.ProviderResponse,
                "ConfigureProviderRefresh": openshell_pb2.ConfigureProviderRefreshResponse,
                "RotateProviderCredential": openshell_pb2.RotateProviderCredentialResponse,
            }.get(method)
            if response_type is None or type(result) is not response_type:
                raise ProviderBootstrapError("invalid_mutation_ack", pending)
            # Acknowledged mutation still happened if currentness is revoked
            # immediately afterwards. Preserve that distinction for cleanup.
            receipt = BootstrapOperationReceipt(method, request.request_id, "applied")
            if method == "ImportProviderProfiles" and not result.imported:
                # This existing typed response explicitly reports that import
                # validation refused the operation before persistence.
                receipt = BootstrapOperationReceipt(method, request.request_id, "none")
            if (
                method == "CreateProvider"
                and type(result) is openshell_pb2.ProviderResponse
                and len(result.provider.metadata.id) <= 256
                and len(result.provider.metadata.name) <= 256
            ):
                receipt = BootstrapOperationReceipt(
                    method,
                    request.request_id,
                    "applied",
                    provider_id=result.provider.metadata.id,
                    provider_name=result.provider.metadata.name,
                    resource_version=result.provider.metadata.resource_version,
                )
            self._record_mutation(receipt, mutation_index)
            self._unknown = None
            self._unsettled_snapshot = None
            try:
                self._check_current()
            except ProviderBootstrapError:
                self._set_unsettled(receipt)
                raise ProviderBootstrapError(
                    "installation_not_current", receipt
                ) from None
        else:
            self._check_current()
        return result

    def _mutation_ready(self) -> None:
        if self._unknown is not None:
            raise ProviderBootstrapError(
                "unsettled_mutation", self._unsettled_receipt()
            )

    def _support(self) -> None:
        response = self._rpc(
            "ListProviderProfiles",
            openshell_pb2.ListProviderProfilesRequest(
                workspace_scope=self._scope(), page_size=1
            ),
        )
        if response.supports_refresh_resource_version_preconditions is not True:
            raise ProviderBootstrapError("resource_version_preconditions_unsupported")

    def _remote_profile(self) -> None:
        response = self._rpc(
            "GetProviderProfile",
            openshell_pb2.GetProviderProfileRequest(
                id=_PROFILE_ID, workspace_scope=self._scope()
            ),
        )
        _check_profile(response.profile, self._profile_pin)
        if response.profile.scope != "workspace":
            raise ProviderBootstrapError("profile_scope_mismatch")

    def _owned(self, ownership: ProviderOwnership) -> None:
        if (
            type(ownership) is not ProviderOwnership
            or ownership.installation_id != self._installation
            or ownership.gateway_url != self._gateway
            or ownership.workspace != self._workspace
            or ownership.profile_sha256 != self._profile_pin
            or not ownership.provider_id
            or ownership.resource_version <= 0
        ):
            raise ProviderBootstrapError("ownership_mismatch")
        failed = False
        try:
            failed = self._require_owned(ownership) is not None
        except Exception:
            failed = True
        if failed:
            raise ProviderBootstrapError("ownership_unproven")

    def current(self, ownership: ProviderOwnership) -> ProviderObservation:
        """Read exact current identity/profile/config; never repair or recreate."""
        self._check_current()
        self._owned(ownership)
        self._remote_profile()
        provider = self._rpc(
            "GetProvider",
            openshell_pb2.GetProviderRequest(
                name=ownership.name, workspace_scope=self._scope()
            ),
        ).provider
        meta = provider.metadata
        if (
            meta.id != ownership.provider_id
            or meta.name != ownership.name
            or meta.workspace != ownership.workspace
            or meta.resource_version < ownership.resource_version
            or meta.HasField("deletion_time")
            or provider.type != _PROFILE_ID
            or provider.profile_workspace != self._workspace
            or _config_hash(provider.config) != ownership.config_sha256
        ):
            raise ProviderBootstrapError("provider_identity_changed")
        self._owned(ownership)
        return ProviderObservation(ownership, meta.resource_version)

    def _verify_applied(
        self, ownership: ProviderOwnership, receipt: BootstrapOperationReceipt
    ) -> ProviderObservation:
        """Retain the actual acknowledgement if its later read cannot settle."""
        try:
            return self.current(ownership)
        except Exception:
            self._set_unsettled(receipt)
            raise ProviderBootstrapError(
                "post_mutation_verification_unsettled", receipt
            ) from None

    def install(
        self,
        name: str,
        *,
        config: Mapping[str, str] | None = None,
        ownership: ProviderOwnership | None = None,
        import_profile: bool = False,
        attempt_id: str | None = None,
    ) -> ProviderOwnership:
        """Explicitly import/create once, or reuse an independently owned ACK.

        There is no automatic Configure/Rotate, credential discovery or retry.
        A conflicting existing name is never adopted. Profile import is
        explicit and create-only at the server; this method never updates it.
        """
        return self._run_attempt(
            "install",
            attempt_id,
            lambda: self._install(
                name, config=config, ownership=ownership, import_profile=import_profile
            ),
        )

    def _install(
        self,
        name: str,
        *,
        config: Mapping[str, str] | None,
        ownership: ProviderOwnership | None,
        import_profile: bool,
    ) -> ProviderOwnership:
        self._support()  # Must precede even import/create on old servers.
        self._mutation_ready()
        _text(name, maximum=256)
        selected_config = dict(config or {})
        if len(selected_config) > 32:
            raise ProviderBootstrapError("invalid_config")
        for key, value in selected_config.items():
            _text(key, maximum=256)
            _text(value, maximum=4096)
        config_pin = _config_hash(selected_config)
        if ownership is not None:
            self._owned(ownership)
            if ownership.name != name or ownership.config_sha256 != config_pin:
                raise ProviderBootstrapError("ownership_mismatch")
            self.current(ownership)
            return ownership
        if import_profile:
            import_request = openshell_pb2.ImportProviderProfilesRequest(
                workspace_scope=self._scope(),
                profiles=[
                    openshell_pb2.ProviderProfileImportItem(profile=self._profile)
                ],
                request_id=str(uuid.uuid4()),
            )
            response = self._rpc(
                "ImportProviderProfiles",
                import_request,
                mutation=True,
            )
            receipt = BootstrapOperationReceipt(
                "ImportProviderProfiles",
                import_request.request_id,
                "applied" if response.imported else "none",
            )
            if not response.imported:
                raise ProviderBootstrapError("profile_import_refused", receipt)
            try:
                if len(response.profiles) != 1:
                    raise ProviderBootstrapError("profile_import_ack_mismatch")
                _check_profile(response.profiles[0], self._profile_pin)
                self._remote_profile()
            except Exception:
                self._set_unsettled(receipt)
                raise ProviderBootstrapError(
                    "post_mutation_verification_unsettled", receipt
                ) from None
        else:
            self._remote_profile()
        request = openshell_pb2.CreateProviderRequest(
            workspace_scope=self._scope(),
            provider=datamodel_pb2.Provider(
                metadata=datamodel_pb2.ObjectMeta(name=name, workspace=self._workspace),
                type=_PROFILE_ID,
                config=selected_config,
                profile_workspace=self._workspace,
            ),
            request_id=str(uuid.uuid4()),
        )
        provider = self._rpc("CreateProvider", request, mutation=True).provider
        meta = provider.metadata
        receipt = BootstrapOperationReceipt(
            "CreateProvider",
            request.request_id,
            "applied",
            provider_id=meta.id if len(meta.id) <= 256 else "",
            provider_name=meta.name if len(meta.name) <= 256 else "",
            resource_version=meta.resource_version,
        )
        if (
            not meta.id
            or meta.name != name
            or meta.workspace != self._workspace
            or meta.resource_version <= 0
            or meta.HasField("deletion_time")
            or provider.type != _PROFILE_ID
            or provider.profile_workspace != self._workspace
            or _config_hash(provider.config) != config_pin
        ):
            self._set_unsettled(receipt)
            raise ProviderBootstrapError("invalid_create_ack", receipt)
        ownership = ProviderOwnership(
            self._installation,
            self._gateway,
            self._workspace,
            name,
            meta.id,
            meta.resource_version,
            self._profile_pin,
            config_pin,
            request.request_id,
        )
        failed = False
        try:
            failed = self._record_created(ownership) is not None
        except Exception:
            failed = True
        if failed:
            self._set_unsettled(receipt)
            raise ProviderBootstrapError("ownership_record_unsettled", receipt)
        self._verify_applied(ownership, receipt)
        return ownership

    @staticmethod
    def _material(
        source: GatewayDefaultChainSource | SecretRefreshSource,
    ) -> dict[str, str]:
        if type(source) not in (GatewayDefaultChainSource, SecretRefreshSource):
            raise ProviderBootstrapError("credential_source_required")
        material = {
            "role_arn": _text(source.role_arn, maximum=2048),
            "aws_region": _text(source.aws_region, maximum=64),
        }
        if (
            not source.role_arn.startswith("arn:aws:iam::")
            or ":role/" not in source.role_arn
        ):
            raise ProviderBootstrapError("invalid_role")
        for key in ("session_name", "external_id"):
            value = getattr(source, key)
            if value:
                material[key] = _text(value, maximum=1024)
        if type(source) is SecretRefreshSource:
            failed = False
            try:
                credentials = source.resolve(source.reference)
                access = credentials.access_key
                secret = credentials.secret_key
                token = credentials.token
                if (
                    not access
                    or not secret
                    or type(access) is not str
                    or type(secret) is not str
                ):
                    failed = True
                if token is not None and type(token) is not str:
                    failed = True
            except Exception:
                failed = True
            if failed:
                raise ProviderBootstrapError("credential_source_incomplete")
            material["aws_access_key_id"] = _text(access, maximum=4096)
            material["aws_secret_access_key"] = _text(secret, maximum=4096)
            if token:
                material["aws_session_token"] = _text(token, maximum=16384)
        return material

    def configure(
        self,
        ownership: ProviderOwnership,
        source: GatewayDefaultChainSource | SecretRefreshSource,
        *,
        attempt_id: str | None = None,
    ) -> ProviderObservation:
        """Configure existing gateway STS refresh against an exact observed ID/RV."""
        return self._run_attempt(
            "configure", attempt_id, lambda: self._configure(ownership, source)
        )

    def _configure(
        self,
        ownership: ProviderOwnership,
        source: GatewayDefaultChainSource | SecretRefreshSource,
    ) -> ProviderObservation:
        self._support()
        self._mutation_ready()
        observed = self.current(ownership)
        material = self._material(source)
        self._check_current()
        request = openshell_pb2.ConfigureProviderRefreshRequest(
            workspace_scope=self._scope(),
            provider=ownership.name,
            credential_key=_CREDENTIAL,
            strategy=_STRATEGY,
            material=material,
            secret_material_keys=[
                key
                for key in ("aws_secret_access_key", "aws_session_token")
                if key in material
            ],
            expected_resource_version=observed.resource_version,
            request_id=str(uuid.uuid4()),
        )
        try:
            self._rpc("ConfigureProviderRefresh", request, mutation=True)
        finally:
            # Python strings cannot be securely zeroed; do not retain a second
            # copy in this helper or expose the secret-annotated request.
            material.clear()
            request.ClearField("material")
        return self._verify_applied(
            ownership,
            BootstrapOperationReceipt(
                "ConfigureProviderRefresh",
                request.request_id,
                "applied",
                provider_id=ownership.provider_id,
                provider_name=ownership.name,
            ),
        )

    def rotate(
        self, ownership: ProviderOwnership, *, attempt_id: str | None = None
    ) -> ProviderObservation:
        """Use existing gateway rotation; never discover credentials or recreate."""
        return self._run_attempt("rotate", attempt_id, lambda: self._rotate(ownership))

    def _rotate(self, ownership: ProviderOwnership) -> ProviderObservation:
        self._support()
        self._mutation_ready()
        observed = self.current(ownership)
        request = openshell_pb2.RotateProviderCredentialRequest(
            workspace_scope=self._scope(),
            provider=ownership.name,
            credential_key=_CREDENTIAL,
            expected_resource_version=observed.resource_version,
            request_id=str(uuid.uuid4()),
        )
        self._rpc("RotateProviderCredential", request, mutation=True)
        return self._verify_applied(
            ownership,
            BootstrapOperationReceipt(
                "RotateProviderCredential",
                request.request_id,
                "applied",
                provider_id=ownership.provider_id,
                provider_name=ownership.name,
            ),
        )

    def refresh_status(
        self, ownership: ProviderOwnership
    ) -> ProviderRefreshObservation:
        """Read existing refresh status without exporting provider error prose."""
        before = self.current(ownership)
        statuses = self._rpc(
            "GetProviderRefreshStatus",
            openshell_pb2.GetProviderRefreshStatusRequest(
                workspace_scope=self._scope(),
                provider=ownership.name,
                credential_key=_CREDENTIAL,
            ),
        ).credentials
        after = self.current(ownership)
        if before != after or len(statuses) != 1:
            raise ProviderBootstrapError("refresh_observation_unavailable")
        status = statuses[0]
        if (
            status.provider_id != ownership.provider_id
            or status.provider != ownership.name
            or status.credential_key != _CREDENTIAL
            or status.strategy != _STRATEGY
            or status.status
            not in {
                "configured",
                "refreshed",
                "rotation_requested",
                "deleting",
                "error",
                "reauthorization_required",
                "configuration_required",
                "investigation_required",
            }
        ):
            raise ProviderBootstrapError("refresh_observation_unavailable")
        times = []
        for name in ("expiration_time", "next_refresh_time"):
            value = getattr(status, name)
            if not status.HasField(name):
                times.append(None)
            elif not (
                -62135596800 <= value.seconds <= 253402300799
                and 0 <= value.nanos < 1_000_000_000
            ):
                raise ProviderBootstrapError("refresh_observation_unavailable")
            else:
                times.append((value.seconds, value.nanos))
        return ProviderRefreshObservation(after, status.status, times[0], times[1])
