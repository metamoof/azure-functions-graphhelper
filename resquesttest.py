# %%

import time
from re import A

from azure.core.credentials import AccessToken, TokenCredential


class MyCredential(TokenCredential):
    def get_token(self, *scopes, **kwargs) -> AccessToken:
        return AccessToken("token", int(time.time() + 300))  # 5 minutes


# %%


def bearer_helper(credential, *scopes, **kwargs):
    token = credential.get_token(*scopes, **kwargs)
    return {"Authorization": "Bearer " + token.token}


import requests
from requests.auth import AuthBase


class AzureIdentityCredentialAdapter(AuthBase):
    def __init__(self, credential, *scopes, **kwargs):
        self._credential = credential
        self._scopes = scopes
        self._kwargs = kwargs
        self._token: AccessToken = AccessToken("", 0)

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        if "Authorization" in r.headers:
            return r
        if self._token.expires_on - time.time() < 60:
            self._token = self._credential.get_token(*self._scopes, **self._kwargs)
        r.headers.update({"Authorization": "Bearer " + self._token.token})
        return r


session = requests.Session()
session.auth = AzureIdentityCredentialAdapter(
    MyCredential, "https://graph.microsoft.com/.default"
)
# %%
session.post(
    "https://webhook.site/2d1a42ac-89fc-415d-b2c9-8b2c7fe8f1d5", json={"hello": "world"}
)
