import asyncio
import base64
from typing import Dict

import pydantic
import rsa
from lxml.html import document_fromstring
from pysteamauth.errors import check_steam_error
from steamlib.api.trade import SteamTrade
from steamlib.api.trade.exceptions import NotFoundMobileConfirmationError
from yarl import URL

from steampassword.exceptions import ErrorSteamPasswordChange
from steampassword.schemas import (
    PasswordChangeParams,
    RSAKey,
)
from steampassword.steam import CustomSteam


class SteamPasswordChange:

    BROWSER = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/'
        '537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
    )

    def __init__(self, steam: CustomSteam):
        self._steam = steam
        self._steam_trade = SteamTrade(steam)

    async def _receive_password_change_params(self) -> PasswordChangeParams:
        response = await self._steam.raw_request(
            method='GET',
            url='https://help.steampowered.com/wizard/HelpChangePassword?redir=store/account/',
            headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,'
                          'image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Referer': 'https://store.steampowered.com/',
                'User-Agent': self.BROWSER,
            },
            allow_redirects=True,
        )
        # Redirect
        if response.history:
            try:
                return PasswordChangeParams(**URL(response.real_url).query)
            except pydantic.ValidationError:
                pass
        html = await response.text()
        page = document_fromstring(html)
        errors = page.cssselect('#error_description')
        if errors:
            raise ErrorSteamPasswordChange(errors[0].text)
        raise ErrorSteamPasswordChange('Password change error')

    async def _login_info_enter_code(self, data: PasswordChangeParams):
        await self._steam.raw_request(
            method='GET',
            url='https://help.steampowered.com/en/wizard/HelpWithLoginInfoEnterCode',
            params={
                's': data.s,
                'account': data.account,
                'reset': data.reset,
                'lost': data.lost,
                'issueid': data.issueid,
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': 1,
                'gamepad': 0,
            },
            headers={
                'Accept': '*/*',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self.BROWSER,
            }
        )

    async def _send_account_recovery_code(self, data: PasswordChangeParams) -> bool:
        response = await self._steam.json_request(
            method='POST',
            url='https://help.steampowered.com/en/wizard/AjaxSendAccountRecoveryCode',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': '1',
                'gamepad': '0',
                's': data.s,
                'method': '8',
                'link': '',
                'n': '1',
            },
            headers={
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://help.steampowered.com',
                'Referer': f'https://help.steampowered.com/ru/wizard/HelpWithLoginInfoEnterCode?s={data.s}&account={data.account}&reset={data.reset}&lost={data.lost}&issueid={data.issueid}',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self.BROWSER,
            }
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])
        success = response['success']
        if isinstance(success, int):
            check_steam_error(response['success'])
        return bool(success)

    async def _poll_account_recovery_confirmation(self, data: PasswordChangeParams) -> Dict[str, bool]:
        response = await self._steam.json_request(
            method='POST',
            url='https://help.steampowered.com/en/wizard/AjaxPollAccountRecoveryConfirmation',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': 1,
                's': data.s,
                'reset': data.reset,
                'lost': data.lost,
                'method': 8,
                'issueid': data.issueid,
                'gamepad': 0,
            },
            headers={
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://help.steampowered.com',
                'User-Agent': self.BROWSER,
                'X-Requested-With': 'XMLHttpRequest',
            },
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])
        return response

    async def _verify_account_recovery_code(self, data: PasswordChangeParams):
        response = await self._steam.json_request(
            method='GET',
            url='https://help.steampowered.com/en/wizard/AjaxVerifyAccountRecoveryCode',
            params={
                'code': '',
                's': data.s,
                'reset': data.reset,
                'lost': data.lost,
                'method': 8,
                'issueid': data.issueid,
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': 1,
                'gamepad': 0,
            },
            headers={
                'Accept': '*/*',
                'User-Agent': self.BROWSER,
                'X-Requested-With': 'XMLHttpRequest',
            },
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])

    async def _account_recovery_get_next_step(self, data: PasswordChangeParams):
        response = await self._steam.json_request(
            method='POST',
            url='https://help.steampowered.com/en/wizard/AjaxAccountRecoveryGetNextStep',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': 1,
                's': data.s,
                'account': data.account,
                'reset': data.reset,
                'issueid': data.issueid,
                'lost': 2,
            },
            headers={
                'Accept': '*/*',
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://help.steampowered.com',
                'User-Agent': self.BROWSER,
            }
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])

    async def _get_rsa_key(self) -> RSAKey:
        response = await self._steam.json_request(
            method='POST',
            url='https://help.steampowered.com/en/login/getrsakey/',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'username': self._steam.login,
            },
            headers={
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://help.steampowered.com',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self.BROWSER,
            }
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])
        return RSAKey.parse_obj(response)

    def _encrypt_password(self, password: str, mod: str, exp: str) -> str:
        publickey_exp = int(exp, 16)  # type: ignore
        publickey_mod = int(mod, 16)  # type: ignore
        public_key = rsa.PublicKey(n=publickey_mod, e=publickey_exp)
        encrypted_password = rsa.encrypt(
            message=password.encode('ascii'),
            pub_key=public_key,
        )
        encrypted_password64 = base64.b64encode(encrypted_password)
        return str(encrypted_password64, 'utf8')

    async def _recovery_verify_password(
            self,
            data: PasswordChangeParams,
            encrypted_password: str,
            rsatimestamp: int
    ):
        response = await self._steam.json_request(
            method='POST',
            url='https://help.steampowered.com/en/wizard/AjaxAccountRecoveryVerifyPassword/',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                's': data.s,
                'lost': 2,
                'reset': 1,
                'password': encrypted_password,
                'rsatimestamp': rsatimestamp,
            },
            headers={
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://help.steampowered.com',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self.BROWSER,
            }
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])

    async def _check_password_available(self, password: str):
        response = await self._steam.json_request(
            url='https://help.steampowered.com/en/wizard/AjaxCheckPasswordAvailable/',
            method='POST',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': 1,
                'password': password,
            },
            headers={
                'Origin': 'https://help.steampowered.com',
                'User-Agent': self.BROWSER,
            },
        )
        if not response['available']:
            raise ErrorSteamPasswordChange('Not password available')

    async def _change_password_request(self, data: PasswordChangeParams, encrypted_password: str, rsatimestamp: int):
        response = await self._steam.json_request(
            method='POST',
            url='https://help.steampowered.com/ru/wizard/AjaxAccountRecoveryChangePassword/',
            data={
                'sessionid': await self._steam.sessionid('help.steampowered.com'),
                'wizard_ajax': 1,
                's': data.s,
                'account': data.account,
                'password': encrypted_password,
                'rsatimestamp': rsatimestamp,
            },
            headers={
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://help.steampowered.com',
                'X-Requested-With': 'XMLHttpRequest',
                'User-Agent': self.BROWSER,
            },
        )
        if response.get('errorMsg'):
            raise ErrorSteamPasswordChange(response['errorMsg'])

    async def change(self, new_password: str):
        if not new_password:
            raise ValueError('Empty new password')
        if new_password == self._steam.password:
            raise ValueError('New password is equal old password')

        await self._steam.login_to_steam()

        params = await self._receive_password_change_params()

        await self._login_info_enter_code(params)
        await self._send_account_recovery_code(params)

        # Confirm password change in mobile app
        for _ in range(3):
            try:
                success = await self._steam_trade.mobile_confirm_by_creator_id(params.s)
                if not success:
                    raise ErrorSteamPasswordChange('Error password change confirmation')
                break
            except NotFoundMobileConfirmationError:
                await asyncio.sleep(2)
        else:
            raise NotFoundMobileConfirmationError('Not found mobile confirmation')

        await self._poll_account_recovery_confirmation(params)
        await self._verify_account_recovery_code(params)
        await self._account_recovery_get_next_step(params)

        # Confirm old password
        key = await self._get_rsa_key()
        await self._recovery_verify_password(
            data=params,
            encrypted_password=self._encrypt_password(self._steam.password, key.mod, key.exp),
            rsatimestamp=key.timestamp,
        )

        # Set new password
        key = await self._get_rsa_key()
        await self._check_password_available(new_password)
        await self._change_password_request(
            data=params,
            encrypted_password=self._encrypt_password(new_password, key.mod, key.exp),
            rsatimestamp=key.timestamp,
        )
