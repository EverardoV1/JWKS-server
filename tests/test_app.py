import jwt
from app import app
from keys import ACTIVE_KEY, EXPIRED_KEY, time_now
from jwt import ExpiredSignatureError


def test_jwks_only_shows_active_key():
    client = app.test_client()
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.get_json()
    assert "keys" in data
    keys = data["keys"]
    assert isinstance(keys, list)
    assert len(keys) == 1  # only active key is published
    k = keys[0]
    assert k["kid"] == ACTIVE_KEY["kid"]
    assert k["kty"] == "RSA"
    assert k["alg"] == "RS256"
    assert "n" in k and "e" in k


def test_auth_returns_valid_token_with_active_kid():
    client = app.test_client()
    r = client.post("/auth")
    assert r.status_code == 200
    token = r.get_json()["token"]

    header = jwt.get_unverified_header(token)
    assert header["kid"] == ACTIVE_KEY["kid"]
    assert header["alg"] == "RS256"

    claims = jwt.decode(token, ACTIVE_KEY["public"], algorithms=["RS256"])
    assert claims["sub"] == "test_user"
    assert claims["exp"] > time_now()


def test_auth_expired_param_uses_expired_kid_and_is_expired():
    client = app.test_client()
    r = client.post("/auth?expired=1")
    assert r.status_code == 200
    token = r.get_json()["token"]

    header = jwt.get_unverified_header(token)
    assert header["kid"] == EXPIRED_KEY["kid"]

    # Expired token should raise
    try:
        jwt.decode(token, EXPIRED_KEY["public"], algorithms=["RS256"])
        assert False, "Expected ExpiredSignatureError"
    except ExpiredSignatureError:
        assert True
