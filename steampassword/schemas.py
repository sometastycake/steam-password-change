from typing import Optional

import pydantic


class PasswordChangeParams(pydantic.BaseModel):
    s: int
    account: int
    reset: int
    issueid: int
    lost: int = 0


class RSAKey(pydantic.BaseModel):
    mod: str
    exp: str
    timestamp: int
    token_gid: Optional[str] = None

    class Config:
        fields = {
            'mod': 'publickey_mod',
            'exp': 'publickey_exp',
        }
