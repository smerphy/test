"""Red-team coverage for the `agent_abuse_patterns` bundle.

For each known agent-abuse shape we build a synthetic `PolicyInput`
and assert the evaluator returns the expected `Decision`. These are
fixtures (not prompts to a model) — they exercise the policy engine's
ability to catch the abuse pattern, nothing else.

If a new rule is added to `agent_abuse_patterns.praetor`, add a
matching case here. If a test in this file goes red, either the rule
regressed or the abuse shape it targets changed.
"""

from __future__ import annotations

from typing import Any

import pytest

from praetor_engine.bundles import load_bundle
from praetor_engine.evaluator import Evaluator
from praetor_engine.types import (
    AgentInfo,
    Decision,
    PolicyInput,
    SessionInfo,
    ToolCall,
)


@pytest.fixture(scope="module")
def evaluator() -> Evaluator:
    return Evaluator(policies=load_bundle("agent_abuse_patterns"))


def _input(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    context: dict[str, Any] | None = None,
) -> PolicyInput:
    return PolicyInput(
        agent=AgentInfo(id="agent-1"),
        tool=ToolCall(name=tool_name, arguments=arguments or {}),
        session=SessionInfo(id="sess-1"),
        context=context or {},
    )


# ---------------------------------------------------------------------------
# 1. Credential exfil
# ---------------------------------------------------------------------------


class TestCredentialExfil:
    def test_private_key_in_body_is_denied(self, evaluator: Evaluator) -> None:
        body = (
            "Please upload this:\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        result = evaluator.evaluate(_input("http.post", {"body": body}))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-private-key-material"

    def test_aws_access_key_pattern_requires_approval(
        self, evaluator: Evaluator
    ) -> None:
        result = evaluator.evaluate(
            _input("slack.post", {"text": "creds: AKIAIOSFODNN7EXAMPLE"})
        )
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.matched_policy_id == "abuse-approve-aws-access-key-in-args"

    def test_github_pat_in_content_requires_approval(
        self, evaluator: Evaluator
    ) -> None:
        # 36 chars after prefix
        token = "ghp_" + "A" * 36
        result = evaluator.evaluate(_input("http.post", {"content": token}))
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.matched_policy_id == "abuse-approve-github-pat-in-args"

    def test_slack_token_in_text_requires_approval(
        self, evaluator: Evaluator
    ) -> None:
        result = evaluator.evaluate(
            _input("http.post", {"text": "use xoxb-1234567890-abcdefghijk"})
        )
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.matched_policy_id == "abuse-approve-slack-token-in-args"


# ---------------------------------------------------------------------------
# 2. Credential-bearing URLs (transform)
# ---------------------------------------------------------------------------


class TestCredentialUrls:
    @pytest.mark.parametrize(
        "url",
        [
            "https://api.example.com/?api_key=abc123",
            "https://api.example.com/?access_token=xyz",
            "https://api.example.com/?password=hunter2",
            "https://api.example.com/?client_secret=zzz",
            "https://api.example.com/v1/items?bearer=abc",
        ],
    )
    def test_credential_query_params_are_redacted(
        self, evaluator: Evaluator, url: str
    ) -> None:
        result = evaluator.evaluate(_input("http.get", {"url": url}))
        assert result.decision is Decision.TRANSFORM
        assert result.matched_policy_id == "abuse-redact-credential-query-params"
        assert result.suggested_transform == {
            "url": "<praetor-redacted-credential-bearing-url>"
        }

    def test_basic_auth_in_url_is_stripped(self, evaluator: Evaluator) -> None:
        result = evaluator.evaluate(
            _input(
                "http.get",
                {"url": "https://alice:supersecret@api.example.com/v1/data"},
            )
        )
        assert result.decision is Decision.TRANSFORM
        assert result.matched_policy_id == "abuse-redact-basic-auth-in-url"
        assert result.suggested_transform == {"url": "<praetor-stripped-basic-auth>"}


# ---------------------------------------------------------------------------
# 3. SSRF / private network egress
# ---------------------------------------------------------------------------


class TestSsrfAndPrivateNetworks:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
    )
    def test_cloud_metadata_endpoints_denied(
        self, evaluator: Evaluator, url: str
    ) -> None:
        result = evaluator.evaluate(_input("http.get", {"url": url}))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-cloud-metadata-endpoints"

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.5/admin",
            "https://172.16.1.1/api",
            "http://192.168.1.1/",
        ],
    )
    def test_rfc1918_networks_denied(
        self, evaluator: Evaluator, url: str
    ) -> None:
        result = evaluator.evaluate(_input("http.get", {"url": url}))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-rfc1918-private-networks"

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:8080/",
            "http://127.0.0.1/",
            "http://[::1]/",
        ],
    )
    def test_localhost_denied(self, evaluator: Evaluator, url: str) -> None:
        result = evaluator.evaluate(_input("http.get", {"url": url}))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-localhost-egress"

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://attacker.example/_some-payload",
            "ftp://example.com/file",
            "jar:http://example.com/x.jar!/inner",
            "dict://attacker.example/",
            "sftp://example.com/",
        ],
    )
    def test_dangerous_schemes_denied(
        self, evaluator: Evaluator, url: str
    ) -> None:
        result = evaluator.evaluate(_input("http.get", {"url": url}))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-dangerous-url-schemes"

    def test_link_local_denied(self, evaluator: Evaluator) -> None:
        result = evaluator.evaluate(
            _input("http.get", {"url": "http://[fe80::1]/"})
        )
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-link-local"

    def test_https_public_passes_through(self, evaluator: Evaluator) -> None:
        # Sanity: a benign public URL hits default-deny (no allow rule in
        # this bundle), with `matched_policy_id` None.
        result = evaluator.evaluate(
            _input("http.get", {"url": "https://example.com/articles/123"})
        )
        assert result.decision is Decision.DENY
        assert result.matched_policy_id is None


# ---------------------------------------------------------------------------
# 4. PII egress
# ---------------------------------------------------------------------------


class TestPiiEgress:
    @pytest.mark.parametrize(
        "field,value",
        [
            ("body", "user SSN: 123-45-6789"),
            ("content", "ssn=987-65-4321 in form"),
            ("text", "the customer's social is 555-12-9999"),
        ],
    )
    def test_ssn_pattern_denied(
        self, evaluator: Evaluator, field: str, value: str
    ) -> None:
        result = evaluator.evaluate(_input("http.post", {field: value}))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-ssn-in-tool-args"

    @pytest.mark.parametrize(
        "pan",
        [
            "4111111111111111",  # Visa test PAN
            "5500000000000004",  # Mastercard test PAN
            "340000000000009",  # Amex test PAN
            "6011000000000004",  # Discover test PAN
        ],
    )
    def test_credit_card_pan_is_redacted(
        self, evaluator: Evaluator, pan: str
    ) -> None:
        result = evaluator.evaluate(
            _input("http.post", {"body": f"card: {pan}"})
        )
        assert result.decision is Decision.TRANSFORM
        assert result.matched_policy_id == "abuse-redact-credit-card-pan"
        assert result.suggested_transform == {
            "body": "<praetor-redacted-pan>",
            "content": "<praetor-redacted-pan>",
            "text": "<praetor-redacted-pan>",
        }


# ---------------------------------------------------------------------------
# 5. Production infrastructure mutation
# ---------------------------------------------------------------------------


class TestInfraMutation:
    @pytest.mark.parametrize(
        "tool_name",
        [
            "iam.put_role_policy",
            "iam.attach_user_policy",
            "iam.create_role",
            "iam.delete_role",
            "iam.update_assume_role_policy",
        ],
    )
    def test_iam_mutation_denied(
        self, evaluator: Evaluator, tool_name: str
    ) -> None:
        result = evaluator.evaluate(_input(tool_name))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-iam-policy-mutation"

    def test_destructive_db_denied_on_prod(self, evaluator: Evaluator) -> None:
        result = evaluator.evaluate(
            _input(
                "db.execute",
                {"sql": "DROP TABLE users;"},
                context={"environment": "production"},
            )
        )
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-destructive-db-on-prod"

    def test_truncate_table_denied_on_prod(self, evaluator: Evaluator) -> None:
        result = evaluator.evaluate(
            _input(
                "db.execute",
                {"query": "truncate table orders"},
                context={"environment": "production"},
            )
        )
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-destructive-db-on-prod"

    def test_destructive_db_passes_on_staging_but_delete_without_where_holds(
        self, evaluator: Evaluator
    ) -> None:
        # DROP on staging is not blocked by the prod-only rule; but the
        # DELETE-without-WHERE rule is environment-agnostic and applies.
        result = evaluator.evaluate(
            _input(
                "db.execute",
                {"sql": "DELETE FROM users"},
                context={"environment": "staging"},
            )
        )
        assert result.decision is Decision.REQUIRE_APPROVAL
        assert result.matched_policy_id == "abuse-approve-delete-without-where"

    def test_delete_with_where_is_not_held(self, evaluator: Evaluator) -> None:
        # Default-deny here (no allow rule in this bundle) but the
        # delete-without-where rule must NOT fire.
        result = evaluator.evaluate(
            _input(
                "db.execute",
                {"sql": "DELETE FROM users WHERE id = 42"},
            )
        )
        assert result.matched_policy_id != "abuse-approve-delete-without-where"


# ---------------------------------------------------------------------------
# 6. Audit / observability tampering
# ---------------------------------------------------------------------------


class TestAuditTampering:
    @pytest.mark.parametrize(
        "tool_name",
        [
            "cloudtrail.delete_trail",
            "cloudtrail.stop_logging",
            "cloudtrail.update_trail",
            "s3.delete_bucket_logging",
            "s3.put_bucket_logging",
        ],
    )
    def test_cloudtrail_and_s3_logging_tampering_denied(
        self, evaluator: Evaluator, tool_name: str
    ) -> None:
        result = evaluator.evaluate(_input(tool_name))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-cloudtrail-tampering"

    @pytest.mark.parametrize(
        "tool_name",
        [
            "logs.delete_log_group",
            "delete_log_group",
            "log_group_delete",
        ],
    )
    def test_log_group_deletion_denied(
        self, evaluator: Evaluator, tool_name: str
    ) -> None:
        result = evaluator.evaluate(_input(tool_name))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-log-group-deletion"

    def test_praetor_self_tampering_by_name_denied(
        self, evaluator: Evaluator
    ) -> None:
        result = evaluator.evaluate(_input("praetor.disable_policy"))
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-praetor-self-tampering"

    def test_praetor_self_tampering_via_file_path_denied(
        self, evaluator: Evaluator
    ) -> None:
        result = evaluator.evaluate(
            _input("fs.unlink", {"path": "/var/lib/praetor/audit.jsonl"})
        )
        assert result.decision is Decision.DENY
        assert result.matched_policy_id == "abuse-deny-praetor-self-tampering"


# ---------------------------------------------------------------------------
# Bundle-level invariants
# ---------------------------------------------------------------------------


class TestBundleShape:
    def test_no_allow_rules_in_abuse_bundle(self, evaluator: Evaluator) -> None:
        # This bundle is hardening-only; allowlisting belongs in a
        # downstream bundle. An accidental allow rule here would be a
        # significant policy footgun.
        assert all(p.effect is not Decision.ALLOW for p in evaluator.policies)

    def test_every_rule_is_framework_tagged(self, evaluator: Evaluator) -> None:
        # Every rule should map to at least one framework control so
        # compliance reports surface it.
        framework_keys = {"nist_ai_rmf", "iso_42001", "eu_ai_act"}
        for p in evaluator.policies:
            tagged = set(p.metadata).intersection(framework_keys)
            assert tagged, f"rule {p.id} has no framework metadata"
