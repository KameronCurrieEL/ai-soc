from soc.web.auth import RANK, has_role, hash_password, valid_username, verify_password


def test_password_hash_roundtrip_and_salt():
    h = hash_password("correct horse")
    assert h.startswith("pbkdf2$") and verify_password("correct horse", h)
    assert not verify_password("wrong", h)
    assert hash_password("x") != hash_password("x")        # random salt -> different hashes
    assert not verify_password("x", "not-a-hash")          # malformed stored value, no crash


def test_valid_username():
    assert valid_username("dana_1") and valid_username("a.b-c")
    assert not valid_username("") and not valid_username("has space") and not valid_username("x" * 41)
    assert not valid_username("drop;table")


def test_role_rank_ordering():
    assert RANK["viewer"] < RANK["analyst"] < RANK["admin"]


def test_has_role_without_session(app_ctx=None):
    # outside a request there is no user; has_role must be False, not raise
    import flask
    app = flask.Flask(__name__)
    app.secret_key = "t"
    with app.test_request_context("/"):
        assert has_role("viewer") is False
