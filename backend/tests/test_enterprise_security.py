from app.security import (
    create_access_token,
    decode_access_token,
    hash_invitation_token,
    hash_password,
    verify_password,
)


def test_password_hash_is_not_plaintext_and_verifies():
    password = "Correct-Horse-Battery-2026!"
    digest = hash_password(password)
    assert digest != password
    assert verify_password(password, digest)
    assert not verify_password("wrong-password", digest)


def test_invitation_token_is_stored_as_one_way_digest():
    token = "sample-invitation-token-value"
    digest = hash_invitation_token(token)
    assert digest != token
    assert len(digest) == 64
    assert digest == hash_invitation_token(token)


def test_access_token_round_trip(monkeypatch):
    from app.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret_key", "test-secret-key-with-at-least-32-characters")
    token, expires_in = create_access_token("00000000-0000-0000-0000-000000000001")
    assert expires_in == settings.access_token_expire_minutes * 60
    assert decode_access_token(token) == "00000000-0000-0000-0000-000000000001"
    assert decode_access_token(token + "tampered") is None
