import random
import secrets
import string


def generate_password(
        min_length: int = 18,
        max_length: int = 18,
        alphabet: str = string.ascii_letters + string.digits,
) -> str:
    if min_length > max_length:
        raise ValueError('Wrong length interval')
    if min_length < 0 or max_length < 0 or max_length > 32:
        raise ValueError('Wrong length value')
    length = random.randint(min_length, max_length)
    return ''.join(secrets.choice(alphabet) for _ in range(length))
