import time

import requests
from azure.core.credentials import AccessToken, TokenCredential
from requests.auth import AuthBase

graph_scope = "https://graph.microsoft.com/.default"


class AzureIdentityCredentialAdapter(AuthBase):
    """
    An Authentication Adapter for azure.identity credentials
    to be used with requests.Session.
    Automatically adds the Authorization header to requests,
    and refreshes the token if it's about to expire.
    """

    def __init__(self, credential: TokenCredential, *scopes, **kwargs):
        """Creates the Adapter

        :param credential: The azure.identity credential to use
        :type credential: TokenCredential
        :param scopes: The scopes to request
        :type scopes: str
        :param kwargs: Additional keyword arguments to pass to the credential
        :type kwargs: Any
        """
        self._credential = credential
        self._scopes = scopes
        self._kwargs = kwargs
        self._token: AccessToken = AccessToken("", 0)

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        """
        Adds the Authorization header to the request, and refreshes the token if it's about to expire.
        """
        if "Authorization" in r.headers:
            return r
        if self._token.expires_on - time.time() < 60:
            self._token = self._credential.get_token(*self._scopes, **self._kwargs)
        r.headers.update({"Authorization": "Bearer " + self._token.token})
        return r


def get_graph_session(credential: TokenCredential, *scopes) -> requests.Session:
    """
    Creates a requests.Session with the given azure.identity credential

    :param credential: The azure.identity credential to use
    :type credential: TokenCredential
    :param scopes: The scopes to request
    :type scopes: str
    :return: A requests.Session with the given credential and scopes
    :rtype: requests.Session
    """
    session = requests.Session()
    session.auth = AzureIdentityCredentialAdapter(credential, *scopes)
    return session


def get_default_graph_session() -> requests.Session:
    """
    Creates a requests.Session with the DefaultAzureCredential credential

    :return: A requests.Session with the DefaultAzureCredential credential
    :rtype: requests.Session
    """
    from azure.identity import DefaultAzureCredential

    return get_graph_session(DefaultAzureCredential(), graph_scope)
