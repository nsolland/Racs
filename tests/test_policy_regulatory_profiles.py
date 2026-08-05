from validators.policy_validator import validate_policy_context


def _base_policy() -> dict:
    return {
        "policy_id": "policy-eu-1",
        "policy_set_ref": "policy-set/eu",
        "policy_set_version": "2026.07.27",
        "evaluation_mode": "strict",
        "valid_from": "2026-07-27T00:00:00Z",
    }


def _regulatory_profile() -> dict:
    return {
        "profile_id": "EU_AI_ACT_OMNIBUS_2026",
        "legal_act_ref": "Regulation (EU) 2026/1744",
        "version": "2026.07.27",
        "jurisdiction": "EU",
        "effective_at": "2026-08-02T00:00:00Z",
        "classification": "not_applicable",
        "active_obligation_ids": ["article_50_transparency"],
        "evidence_refs": ["receipt:disclosure:123"],
        "accountable_owner_ref": "role:legal-owner",
        "profile_digest": "sha256:abc123",
    }


def test_valid_regulatory_profile_is_accepted() -> None:
    policy = _base_policy()
    policy["regulatory_profiles"] = [_regulatory_profile()]

    assert validate_policy_context(policy) == []


def test_missing_accountable_owner_is_rejected() -> None:
    policy = _base_policy()
    profile = _regulatory_profile()
    del profile["accountable_owner_ref"]
    policy["regulatory_profiles"] = [profile]

    assert "policy_context.regulatory_profiles[0].accountable_owner_ref: is required" in validate_policy_context(policy)


def test_regulatory_profile_must_not_be_executable_code() -> None:
    policy = _base_policy()
    profile = _regulatory_profile()
    profile["active_obligation_ids"] = "article_50_transparency"
    policy["regulatory_profiles"] = [profile]

    assert "policy_context.regulatory_profiles[0].active_obligation_ids: must be a list of strings" in validate_policy_context(policy)
