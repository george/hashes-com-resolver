import hashlib

from resolver import hash_resolver


def test_email() -> None:
    hashed_content = hashlib.md5(b'test@gmail.com').hexdigest()

    assert hash_resolver.decrypt_hash(hashed_content) == 'test@gmail.com'
