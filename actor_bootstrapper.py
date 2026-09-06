"""Automatic provisioning of isolated principals for authorization testing."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from runtime_executor import RequestExecutor
from response_outcome import result_succeeded
from state_store import ActorContext, MultiActorContextStore, StateStore

log = logging.getLogger("actor_bootstrapper")


@dataclass
class BootstrapResult:
    success: bool
    actors: MultiActorContextStore = field(default_factory=MultiActorContextStore)
    owner_state: Optional[StateStore] = None
    signup_api_id: str = ""
    login_api_id: str = ""
    errors: List[str] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)


class ActorBootstrapper:
    """Discover auth operations and provision isolated, role-aware actors."""

    SIGNUP_RE = re.compile(r"signup|sign[_-]?up|register|registration|create[_-]?(user|account)", re.I)
    LOGIN_RE = re.compile(r"login|log[_-]?in|signin|sign[_-]?in|authenticate|issue[_-]?token", re.I)
    EXCLUDED_AUTH_RE = re.compile(r"logout|refresh|forgot|reset|verify|otp|captcha", re.I)
    IDENTITY_RE = re.compile(
        r"(^|[/._-])(me|whoami|profile|current[_-]?(user|account)|get[_-]?me)([/._-]|$)",
        re.I,
    )
    ROLE_FIELD_RE = re.compile(
        r"^(role|userrole|accountrole|accounttype|accesslevel|permissiongroup)$",
        re.I,
    )
    SENSITIVE_FIELD_RE = re.compile(
        r"password|passwd|secret|token|cookie|session|credential|api[_-]?key",
        re.I,
    )

    def __init__(self, operations: List[Dict], executor: RequestExecutor,
                 identity_config: Optional[Dict[str, Any]] = None):
        self.operations = operations
        self.executor = executor
        self.identity_config = dict(identity_config or {})
        self.audit_events: List[Dict[str, Any]] = []
        self._signup_attempts: Dict[str, Dict[str, Any]] = {}

    def discover_auth_operations(self) -> Tuple[Optional[Dict], Optional[Dict]]:
        signup = self._best_match(self.SIGNUP_RE, exclude=None)
        login = self._best_match(self.LOGIN_RE, exclude=self.EXCLUDED_AUTH_RE)
        return signup, login

    def discover_identity_operation(self) -> Optional[Dict]:
        # Dataset-specific configuration is authoritative. This avoids relying
        # on naming conventions for action-style APIs such as user.profile.get.
        configured_id = self.identity_config.get("identity_operation") \
            or self.identity_config.get("identity_operation_id")
        configured_path = self.identity_config.get("identity_path")
        if configured_id or configured_path:
            for operation in self.operations:
                if operation.get("method", "GET").upper() != "GET":
                    continue
                if configured_id and str(operation.get("id", "")) == str(configured_id):
                    return operation
                if configured_path and str(operation.get("path", "")) == str(configured_path):
                    return operation

        candidates = []
        for operation in self.operations:
            if operation.get("method", "GET").upper() != "GET":
                continue
            text = " ".join((
                str(operation.get("id", "")),
                str(operation.get("path", "")),
            ))
            if not self.IDENTITY_RE.search(text):
                continue
            path = str(operation.get("path", "")).rstrip("/").lower()
            score = 10 if path.endswith("/me") else 5
            score -= len(operation.get("inputs", {}) or {})
            candidates.append((score, operation))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None

    def validate_actor(self, state: StateStore) -> Tuple[Optional[bool], str]:
        """Preflight the token principal without relying on later endpoint errors."""
        identity_operation = self.discover_identity_operation()
        if identity_operation is None:
            return None, "No current-user identity endpoint found in OpenAPI"
        result = self.executor.execute_request(
            identity_operation,
            state,
            allow_repair=False,
        )
        if result_succeeded(result):
            state.freeze_actor_identity()
            state.mark_auth_identity(True, f"verified via {identity_operation.get('id')}")
            return True, "identity verified"
        state.mark_auth_identity(False, result.get("outcome_reason") or f"HTTP {result.get('status')}")
        return False, state.get_auth_context()["reason"]

    def _best_match(self, pattern: re.Pattern, exclude: Optional[re.Pattern]) -> Optional[Dict]:
        candidates = []
        for operation in self.operations:
            method = operation.get("method", "GET").upper()
            if method not in ("POST", "PUT"):
                continue
            tags = " ".join(str(tag) for tag in operation.get("tags", []))
            text = " ".join((
                str(operation.get("id", "")),
                str(operation.get("path", "")),
                tags,
                str(operation.get("summary", "")),
                str(operation.get("description", "")),
            ))
            if not pattern.search(text) or (exclude and exclude.search(text)):
                continue
            input_names = {
                str(meta.get("original", name) if isinstance(meta, dict) else name).lower()
                for name, meta in (operation.get("inputs", {}) or {}).items()
            }
            score = 0
            score += 4 if method == "POST" else 1
            score += 3 if any("password" in name or name == "pass" for name in input_names) else 0
            score += 2 if any("email" in name or "username" in name or "number" in name for name in input_names) else 0
            score -= len(input_names) / 100.0
            candidates.append((score, operation))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None

    @classmethod
    def _discover_role_input(cls, operation: Dict) -> Tuple[str, List[Any]]:
        """Return a role-like input and its declared values without app assumptions."""
        for field_name, raw_meta in (operation.get("inputs", {}) or {}).items():
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            original = str(meta.get("original", field_name))
            normalized = re.sub(r"[-_.\s]", "", original)
            enum_values = list(meta.get("enum", []) or [])
            if enum_values and cls.ROLE_FIELD_RE.fullmatch(normalized):
                return original, enum_values
        return "", []

    @staticmethod
    def _spread_enum_values(values: List[Any], count: int) -> List[Any]:
        """Select diverse declared values while preserving OpenAPI ordering."""
        if not values or count <= 0:
            return []
        if count == 1 or len(values) == 1:
            return [values[0]] * count
        return [
            values[round(index * (len(values) - 1) / (count - 1))]
            for index in range(count)
        ]

    @classmethod
    def _redact(cls, value: Any, key: str = "") -> Any:
        if cls.SENSITIVE_FIELD_RE.search(str(key)):
            return "***"
        if isinstance(value, dict):
            return {str(k): cls._redact(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._redact(item, key) for item in value]
        return value

    @classmethod
    def _find_effective_role(cls, value: Any, preferred_field: str = "") -> Any:
        preferred = re.sub(r"[-_.\s]", "", preferred_field)
        if isinstance(value, dict):
            # Prefer the field explicitly declared by the signup schema.
            for key, child in value.items():
                normalized = re.sub(r"[-_.\s]", "", str(key))
                if preferred and normalized.casefold() == preferred.casefold() \
                        and not isinstance(child, (dict, list)):
                    return child
            for key, child in value.items():
                normalized = re.sub(r"[-_.\s]", "", str(key))
                if cls.ROLE_FIELD_RE.fullmatch(normalized) \
                        and not isinstance(child, (dict, list)):
                    return child
            for child in value.values():
                found = cls._find_effective_role(child, preferred_field)
                if found not in (None, ""):
                    return found
        elif isinstance(value, list):
            for child in value:
                found = cls._find_effective_role(child, preferred_field)
                if found not in (None, ""):
                    return found
        return None

    def _sync_effective_role(self, state: StateStore, exec_result: Dict,
                             preferred_field: str = "") -> Any:
        role = self._find_effective_role(
            exec_result.get("raw_response"), preferred_field
        )
        if role in (None, ""):
            for key in ("user_role", preferred_field, "role"):
                if key and state.get(key) not in (None, ""):
                    role = state.get(key)
                    break
        if role not in (None, ""):
            state.update("actor_role", str(role))
        return role

    def _record_auth_event(self, operation: Dict, actor_id: str, stage: str,
                           exec_result: Dict, requested_role: Any = None,
                           effective_role: Any = None,
                           performed_by: str = "") -> None:
        transports = []
        for kind, field_name in (
            ("header", "sent_headers"),
            ("query", "sent_query"),
            ("cookie", "sent_cookies"),
        ):
            for name in (exec_result.get(field_name, {}) or {}):
                transports.append({
                    "kind": kind, "name": str(name), "present": True,
                    "source": "request",
                })
        for transport in (
                exec_result.get("auth_context", {}).get("transports", []) or []):
            if not isinstance(transport, dict):
                continue
            descriptor = {
                "kind": str(transport.get("kind", "")),
                "name": str(transport.get("name", "")),
                "present": True,
                "source": str(transport.get("source", "response")),
            }
            if descriptor["kind"] and descriptor["name"] and descriptor not in transports:
                transports.append(descriptor)
        self.audit_events.append({
            "stage": stage,
            "actor_id": actor_id,
            "performed_by": performed_by or actor_id,
            "api_id": operation.get("id", ""),
            "method": str(operation.get("method", "POST")).upper(),
            "path": exec_result.get("url", operation.get("path", "")),
            "status": exec_result.get("status", 0),
            "successful": result_succeeded(exec_result),
            "outcome_reason": exec_result.get("outcome_reason", ""),
            "request_payload": self._redact(exec_result.get("sent_payload", {})),
            "response_body": self._redact(exec_result.get("raw_response")),
            "requested_role": requested_role,
            "effective_role": effective_role,
            "auth_transports": transports,
        })

    @staticmethod
    def _credential_group(field_name: str) -> str:
        """Normalize conventional credential aliases without dataset knowledge."""
        normalized = re.sub(r"[-_.\s]", "", str(field_name)).casefold()
        aliases = {
            "username": {"username", "user", "login", "loginname", "userid", "name"},
            "email": {"email", "emailaddress"},
            "password": {"password", "passwd", "pass", "passphrase"},
            "phone": {"phone", "mobile", "phonenumber", "mobilenumber"},
        }
        for group, names in aliases.items():
            if normalized in names:
                return group
        return ""

    def _discover_account_provisioner(self, signup: Dict, login: Dict) -> Optional[Dict]:
        """Find an authenticated operation capable of creating login principals."""
        excluded_ids = {signup.get("id"), login.get("id")}
        candidates = []
        for operation in self.operations:
            if operation.get("id") in excluded_ids:
                continue
            if str(operation.get("method", "GET")).upper() not in {"POST", "PUT"}:
                continue
            text = " ".join((
                str(operation.get("id", "")),
                str(operation.get("path", "")),
            ))
            if re.search(
                r"login|signin|signup|register|logout|refresh|forgot|reset|otp|captcha",
                text,
                re.I,
            ):
                continue
            groups = {
                self._credential_group(
                    meta.get("original", name) if isinstance(meta, dict) else name
                )
                for name, meta in (operation.get("inputs", {}) or {}).items()
            }
            if "password" not in groups or not groups.intersection({"username", "email", "phone"}):
                continue
            role_field, role_values = self._discover_role_input(operation)
            score = 0
            score += 10 if operation.get("security_required") else 0
            score += 3 if str(operation.get("method", "")).upper() == "POST" else 1
            score += 2 if role_field and role_values else 0
            score += sum(
                1 for meta in (operation.get("inputs", {}) or {}).values()
                if isinstance(meta, dict) and meta.get("required")
            )
            candidates.append((score, operation))
        return max(candidates, key=lambda item: item[0])[1] if candidates else None

    @staticmethod
    def _new_actor_state(actor_id: str, base_state: Dict) -> StateStore:
        state_data = dict(base_state)
        for key in ("auth_token", "refresh_token", "auth_cookies"):
            state_data.pop(key, None)
        state_data["actor_id"] = actor_id
        state_data["actor_role"] = ""
        return StateStore(state_data)

    def _provision_actor(self, actor_id: str, creator_state: StateStore,
                         signup: Dict, login: Dict, base_state: Dict,
                         requested_role: Any = None) -> Tuple[Optional[StateStore], str]:
        provisioner = self._discover_account_provisioner(signup, login)
        signup_result = self._signup_attempts.get(actor_id, {})
        source_payload = dict(signup_result.get("sent_payload", {}) or {})
        if provisioner is None:
            return None, "No authenticated account-provisioning operation found in OpenAPI"

        direct_values = {
            re.sub(r"[-_.\s]", "", str(key)).casefold(): value
            for key, value in source_payload.items()
        }
        grouped_values = {}
        for key, value in source_payload.items():
            group = self._credential_group(key)
            if group:
                grouped_values[group] = value

        payload_patch = {}
        for field_name, raw_meta in (provisioner.get("inputs", {}) or {}).items():
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            original = str(meta.get("original", field_name))
            normalized = re.sub(r"[-_.\s]", "", original).casefold()
            group = self._credential_group(original)
            if normalized in direct_values:
                payload_patch[original] = direct_values[normalized]
            elif group and group in grouped_values:
                payload_patch[original] = grouped_values[group]

        role_field, allowed_roles = self._discover_role_input(provisioner)
        provision_role = requested_role if requested_role in allowed_roles else None
        if provision_role is None and allowed_roles:
            provision_role = allowed_roles[-1]
        if role_field and provision_role is not None:
            payload_patch[role_field] = provision_role

        patched_groups = {
            self._credential_group(key) for key in payload_patch
        }
        if "password" not in patched_groups \
                or not patched_groups.intersection({"username", "email", "phone"}):
            return None, "Signup and provisioning schemas do not share reusable login credentials"

        provision_state = creator_state.clone()
        provision_result = self.executor.execute_request(
            provisioner,
            provision_state,
            payload_patch=payload_patch,
            allow_repair=True,
        )
        effective_role = self._find_effective_role(
            provision_result.get("raw_response"), role_field
        )
        self._record_auth_event(
            provisioner,
            actor_id,
            "provision",
            provision_result,
            requested_role=provision_role,
            effective_role=effective_role,
            performed_by=creator_state.get("actor_id", ""),
        )
        if not result_succeeded(provision_result):
            return None, (
                f"authenticated provisioning failed with HTTP {provision_result.get('status')} "
                f"via {provisioner.get('id')}"
            )

        state = self._new_actor_state(actor_id, base_state)
        sent_payload = provision_result.get("sent_payload", payload_patch) or payload_patch
        for key, value in sent_payload.items():
            if self._credential_group(key) and value not in (None, ""):
                state.update(str(key), value)
        if effective_role not in (None, ""):
            state.update("actor_role", str(effective_role))
        state.freeze_actor_credentials()

        login_result = self.executor.execute_request(login, state, allow_repair=True)
        login_role = self._sync_effective_role(state, login_result, role_field)
        effective_role = login_role if login_role not in (None, "") else effective_role
        self._record_auth_event(
            login,
            actor_id,
            "signin",
            login_result,
            requested_role=provision_role,
            effective_role=effective_role,
        )
        if not result_succeeded(login_result):
            return None, f"provisioned actor login failed with HTTP {login_result.get('status')}"
        if not self._has_auth_session(state):
            return None, "provisioned actor login succeeded but no auth transport was extracted"

        state.freeze_actor_identity()
        state.freeze_actor_credentials()
        if effective_role not in (None, ""):
            state.update("actor_role", str(effective_role))
        state.mark_auth_identity(True, "provisioned and authenticated")
        return state, ""

    def bootstrap(self, base_state: Optional[Dict] = None) -> BootstrapResult:
        self.audit_events = []
        self._signup_attempts = {}
        signup, login = self.discover_auth_operations()
        result = BootstrapResult(
            success=False,
            signup_api_id=signup.get("id", "") if signup else "",
            login_api_id=login.get("id", "") if login else "",
        )
        if signup is None:
            result.errors.append("No supported signup/register operation found in OpenAPI")
            result.events = list(self.audit_events)
            return result
        if login is None:
            result.errors.append("No supported login/signin operation found in OpenAPI")
            result.events = list(self.audit_events)
            return result

        states = []
        actor_ids = ("owner_a", "user_b")
        role_field, declared_roles = self._discover_role_input(signup)
        requested_roles = self._spread_enum_values(declared_roles, len(actor_ids))
        for index, actor_id in enumerate(actor_ids):
            requested_role = requested_roles[index] if requested_roles else None
            state, error = self._bootstrap_actor(
                actor_id,
                signup,
                login,
                base_state or {},
                role_field=role_field,
                requested_role=requested_role,
            )
            if error:
                # Some APIs allow self-registration only for the initial
                # principal. Reuse the confirmed creator actor through a
                # schema-compatible authenticated provisioning operation.
                if states:
                    provisioned_state, provision_error = self._provision_actor(
                        actor_id,
                        creator_state=states[0],
                        signup=signup,
                        login=login,
                        base_state=base_state or {},
                        requested_role=requested_role,
                    )
                    if provisioned_state is not None:
                        states.append(provisioned_state)
                        continue
                    error = f"{error}; fallback failed: {provision_error}"
                result.errors.append(error)
                result.events = list(self.audit_events)
                return result
            states.append(state)

        # BOLA requires two distinct principals with the same effective role.
        # A common bootstrap policy creates the first account as HOST and only
        # lets that HOST provision USER accounts. In that case create a third
        # principal matching the non-privileged actor instead of pairing HOST
        # with USER (which belongs to BFLA, not BOLA).
        role_groups = {}
        for state in states:
            role = str(state.get("actor_role", "")).strip().casefold()
            if role and role not in {"unknown", "anonymous", "none", "null"}:
                role_groups.setdefault(role, []).append(state)
        same_role_pair = next(
            (group[:2] for group in role_groups.values() if len(group) >= 2),
            None,
        )
        desired_role = str(states[-1].get("actor_role", "")).strip() if states else ""
        desired_role_known = desired_role.casefold() not in {
            "", "unknown", "anonymous", "none", "null"
        }
        if same_role_pair is None and len(states) >= 2 and desired_role_known:
            requested_role = (
                requested_roles[-1] if requested_roles else next(
                    (value for value in declared_roles
                     if str(value).casefold() == str(desired_role).casefold()),
                    desired_role,
                )
            )
            extra_state, extra_error = self._bootstrap_actor(
                "user_c", signup, login, base_state or {},
                role_field=role_field, requested_role=requested_role,
            )
            if extra_state is None:
                extra_state, extra_error = self._provision_actor(
                    "user_c", creator_state=states[0], signup=signup, login=login,
                    base_state=base_state or {}, requested_role=requested_role,
                )
            if extra_state is not None:
                states.append(extra_state)
                if str(extra_state.get("actor_role", "")).casefold() == \
                        str(desired_role).casefold():
                    same_role_pair = [states[-2], extra_state]
            elif extra_error:
                log.warning(f"[Bootstrap] Same-role BOLA pair unavailable: {extra_error}")

        for state in states:
            actor = self._actor_from_state(state)
            result.actors.add(actor)
        result.actors.add(ActorContext(actor_id="anonymous", role="anonymous"))
        result.owner_state = same_role_pair[0] if same_role_pair else states[0]
        result.success = True
        result.events = list(self.audit_events)
        return result

    def _bootstrap_actor(self, actor_id: str, signup: Dict, login: Dict,
                         base_state: Dict, role_field: str = "",
                         requested_role: Any = None) -> Tuple[Optional[StateStore], str]:
        # Never leak manually configured auth into an automatically-created actor.
        state = self._new_actor_state(actor_id, base_state)

        signup_kwargs = {"allow_repair": True}
        if role_field and requested_role is not None:
            signup_kwargs["payload_patch"] = {role_field: requested_role}
        signup_result = self.executor.execute_request(signup, state, **signup_kwargs)
        self._signup_attempts[actor_id] = signup_result
        effective_role = self._sync_effective_role(state, signup_result, role_field)
        self._record_auth_event(
            signup, actor_id, "signup", signup_result,
            requested_role=requested_role,
            effective_role=effective_role,
        )
        if not result_succeeded(signup_result):
            return None, (
                f"Actor {actor_id}: signup failed with HTTP {signup_result.get('status')} "
                f"({signup_result.get('outcome_reason') or 'application rejected request'}) "
                f"via {signup.get('id')}"
            )

        # Recovery starts with a stale principal snapshot. Signup may have
        # generated a new username/email, so promote those fresh credentials
        # before the immediately-following login.
        state.freeze_actor_identity()
        state.freeze_actor_credentials()

        # Login is always verified even when signup already set a session. This
        # proves that the generated credentials are reusable and keeps the two
        # lifecycle outcomes independently visible in the report.
        login_result = self.executor.execute_request(login, state, allow_repair=True)
        login_role = self._sync_effective_role(state, login_result, role_field)
        effective_role = login_role if login_role not in (None, "") else effective_role
        self._record_auth_event(
            login, actor_id, "signin", login_result,
            requested_role=requested_role,
            effective_role=effective_role,
        )
        if not result_succeeded(login_result):
            hint = login_result.get("response_text", "").lower()
            suffix = " (OTP/CAPTCHA/manual verification required)" if re.search(
                r"otp|verify|captcha|two.?factor|2fa", hint
            ) else ""
            return None, (
                f"Actor {actor_id}: login failed with HTTP {login_result.get('status')}"
                f" via {login.get('id')}{suffix}"
            )

        if not self._has_auth_session(state):
            return None, f"Actor {actor_id}: login succeeded but no token or auth cookie was extracted"
        # Values returned by later public/list APIs must not replace the
        # username/user_id that belongs to this authenticated session.
        state.freeze_actor_identity()
        state.freeze_actor_credentials()
        if effective_role not in (None, ""):
            state.update("actor_role", str(effective_role))
        state.mark_auth_identity(True, "registered and authenticated")
        return state, ""

    def recover_actor(self, state: StateStore) -> Tuple[bool, str]:
        """Refresh an actor session, or recreate it when its token subject vanished."""
        signup, login = self.discover_auth_operations()
        if login is None:
            return False, "No supported login/signin operation found in OpenAPI"

        state.memory.pop("auth_token", None)
        state.memory.pop("refresh_token", None)
        state.memory.pop("auth_cookies", None)

        login_result = self.executor.execute_request(
            login,
            state,
            allow_repair=False,
            allow_auth_recovery=False,
        )
        if result_succeeded(login_result) and self._has_auth_session(state):
            state.freeze_actor_identity()
            state.mark_auth_identity(True, "session refreshed by login")
            return True, "session refreshed"

        if signup is None:
            return False, "Login failed and no signup/register operation is available"

        role_field, declared_roles = self._discover_role_input(signup)
        previous_role = state.get("actor_role")
        requested_role = previous_role if previous_role in declared_roles else None
        recovered_state, error = self._bootstrap_actor(
            state.get("actor_id", "recovered_actor"),
            signup,
            login,
            dict(state.memory),
            role_field=role_field,
            requested_role=requested_role,
        )
        if error or recovered_state is None:
            return False, error or "Actor recreation failed"

        state.replace_auth_context_from(recovered_state)
        state.mark_auth_identity(True, "identity recreated and authenticated")
        return True, "identity recreated"

    @staticmethod
    def _has_auth_session(state: StateStore) -> bool:
        return state.has_authentication()

    @staticmethod
    def _actor_from_state(state: StateStore) -> ActorContext:
        credentials = {
            str(key): value for key, value in state.memory.items()
            if ActorBootstrapper._credential_group(key) and value not in (None, "")
        }
        for key, value in state.get_actor_credentials().items():
            credentials.setdefault(key, value)
        return ActorContext(
            actor_id=state.get("actor_id"),
            role=state.get("actor_role") or "unknown",
            auth_token=state.get("auth_token", ""),
            refresh_token=state.get("refresh_token", ""),
            credentials=credentials,
            cookies=dict(state.get("auth_cookies", {}) or {}),
            auth_transports=state.get_auth_transports(),
        )
