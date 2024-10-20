# Steam-password-change

[![Python: versions](
https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)]()


## Description

Script changes Steam account password. It works only for accounts with Steam Guard

## Usage

```python
from steampassword.chpassword import SteamPasswordChange
from steampassword.steam import CustomSteam
from steampassword.utils import generate_password


async def main():
    steam = CustomSteam(
        login='login',
        password='password',
        shared_secret='shared_secret',
        identity_secret='identity_secret',
        device_id='device_id',
        steamid=76560000000000000,
    )
    newpassword = generate_password()
    await SteamPasswordChange(steam).change(newpassword)
```


## Licence

MIT
