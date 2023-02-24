import json
from typing import (
    Any,
    Dict,
    Optional,
)

import aiohttp
from pysteamauth.abstract import (
    CookieStorageAbstract,
    RequestStrategyAbstract,
)
from pysteamauth.auth import Steam
from urllib3.util import parse_url


class CustomSteam(Steam):

    def __init__(
            self, login: str,
            password: str,
            steamid: Optional[int] = None,
            shared_secret: Optional[str] = None,
            identity_secret: Optional[str] = None,
            device_id: Optional[str] = None,
            cookie_storage: Optional[CookieStorageAbstract] = None,
            request_strategy: Optional[RequestStrategyAbstract] = None,
    ):
        super().__init__(
            login=login, password=password, steamid=steamid, shared_secret=shared_secret,
            identity_secret=identity_secret, device_id=device_id, cookie_storage=cookie_storage,
            request_strategy=request_strategy,
        )

    @property
    def password(self) -> str:
        return self._password

    async def json_request(self, url: str, method: str = 'GET', **kwargs: Any) -> Dict:
        return json.loads(await super().request(url, method, **kwargs))

    async def raw_request(self, url: str, method: str = 'GET', **kwargs: Any) -> aiohttp.ClientResponse:
        return await self._requests.request(
            url=url, method=method, cookies=await self.cookies(parse_url(url).host), **kwargs,
        )
