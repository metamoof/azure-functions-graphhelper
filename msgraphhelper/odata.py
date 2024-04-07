import json
import urllib.parse
from typing import Any, Optional

import requests
from attr import dataclass


class ODataPaginator:
    """
    A class to paginate through OData responses synchronously.

    Just wrap this around the response you get from an Odata source, and iterate through it to get all the values.
    It will automatically make additional requests to get more data if there is more data to get.

    :param initial_data: The initial response to start paginating from
    :type initial_data: requests.Response
    :param session: The requests.Session to use for making additional requests
    :type session: requests.Session
    """

    def __init__(
        self, initial_data: requests.Response | dict | str, session: requests.Session
    ):
        self.responses = [initial_data]
        self.session = session
        return super().__init__()

    def __iter__(self):
        for current_resp in self.responses:
            if type(current_resp) == dict:
                current_data = current_resp
            elif type(current_resp) == str:
                current_data = json.loads(current_resp)
            elif type(current_resp) == requests.Response:
                current_data = current_resp.json()
            else:
                raise TypeError("Could not work out the type of the response")
            for value in current_data["value"]:
                yield value

        while "@odata.nextLink" in current_data and current_data["value"] != []:
            current_resp = self.session.get(current_data["@odata.nextLink"])
            self.responses.append(current_resp)
            current_data = current_resp.json()
            for value in current_data["value"]:
                yield value


class ODataBatchRequest(dict):
    """
    A class to batch multiple OData requests into a one or more batch requests.

    :param session: The requests.Session to use for making the request
    :type session: requests.Session
    :param batch_url: The URL to send the batch request to
    :type batch_url: str
    :param max_batch_size: The maximum number of requests to send in a single batch, defaults to 100
    :type max_batch_size: int, optional
    :param continue_on_error: Whether to continue processing requests if one fails, defaults to True
    :type continue_on_error: Optional[bool], optional
    :param isolation_snapshot: Whether to use an isolation snapshot, defaults to True
    :type isolation_snapshot: Optional[bool], optional
    """

    def __init__(
        self,
        session: requests.Session,
        batch_url: str = "http://graph.microsoft.com/v1.0/$batch",
        max_batch_size: int = 100,
        continue_on_error: Optional[bool] = True,
        isolation_snapshot: Optional[bool] = True,
    ):
        self.session = session
        self.batch_url = batch_url
        self.max_batch_size = max_batch_size
        self.responses = []
        self.continue_on_error = continue_on_error
        self.isolation_snapshot = isolation_snapshot
        return super().__init__()

    def request(
        self,
        id: str,
        *,
        method: str,
        url: str,
        body: dict = {},
        headers: dict = {},
        params: dict = {},
    ) -> dict[str, Any]:
        """
        Add a request to the batch

        :param id: The ID of the request
        :type id: str
        :param method: The HTTP method to use
        :type method: str
        :param url: The URL to request
        :type url: str
        :param body: The data to send in the request, must be JSON serialisable, defaults to {}
        :type body: dict, optional
        :param headers: The headers to send in the request, defaults to {}
        :type headers: dict, optional
        :param params: The query parameters to send, defaults to {}
        :type params: dict, optional
        :return: The request dict as will be sent in the batch
        :rtype: dict[str, Any]
        """
        headers = dict(headers)
        if params:
            quoted = urllib.parse.urlencode(params)
            if "?" in url:
                url += "&" + quoted
            else:
                url += "?" + quoted

        operation: dict[str, Any] = {
            "id": id,
            "method": method,
            "url": url,
        }
        if headers:
            operation["headers"] = headers
        if body:
            operation["body"] = body
        self[id] = operation
        return operation

    def get(
        self,
        id: str,
        url: str,
        *,
        headers: dict = {},
        params: dict = {},
    ) -> dict[str, Any]:
        """
        Add a GET request to the batch

        :param id: The ID of the request
        :type id: str
        :param url: The URL to request
        :type url: str
        :param params: The query parameters to send, defaults to {}
        :type params: dict, optional
        :param headers: The headers to send in the request, defaults to {}
        :type headers: dict, optional
        :return: The request dict as will be sent in the batch
        :rtype: dict[str, Any]
        """
        return self.request(
            id=id, method="GET", url=url, params=params, headers=headers
        )

    def post(
        self,
        id: str,
        url: str,
        body: dict = {},
        *,
        headers: dict = {},
        params: dict = {},
    ) -> dict[str, Any]:
        """
        Add a POST request to the batch

        :param id: The ID of the request
        :type id: str
        :param url: The URL to request
        :type url: str
        :param body: The data to send in the request, must be JSON serialisable, defaults to {}
        :type body: dict, optional
        :param headers: The headers to send in the request, defaults to {}
        :type headers: dict, optional
        :param params: The query parameters to send, defaults to {}
        :type params: dict, optional
        :return: The request dict as will be sent in the batch
        :rtype: dict[str, Any]
        """
        return self.request(
            id=id, method="POST", url=url, body=body, headers=headers, params=params
        )

    def patch(
        self,
        id: str,
        url: str,
        body: dict = {},
        *,
        headers: dict = {},
        params: dict = {},
    ) -> dict[str, Any]:
        """
        Add a PATCH request to the batch

        :param id: The ID of the request
        :type id: str
        :param url: The URL to request
        :type url: str
        :param body: The data to send in the request, must be JSON serialisable, defaults to {}
        :type body: dict, optional
        :param headers: The headers to send in the request, defaults to {}
        :type headers: dict, optional
        :param params: The query parameters to send, defaults to {}
        :type params: dict, optional
        :return: The request dict as will be sent in the batch
        :rtype: dict[str, Any]
        """
        return self.request(
            id=id, method="PATCH", url=url, body=body, headers=headers, params=params
        )

    def put(
        self,
        id: str,
        url: str,
        body: dict = {},
        *,
        headers: dict = {},
        params: dict = {},
    ) -> dict[str, Any]:
        """
        Add a PUT request to the batch

        :param id: The ID of the request
        :type id: str
        :param url: The URL to request
        :type url: str
        :param body: The data to send in the request, must be JSON serialisable, defaults to {}
        :type body: dict, optional
        :param headers: The headers to send in the request, defaults to {}
        :type headers: dict, optional
        :param params: The query parameters to send, defaults to {}
        :type params: dict, optional
        :return: The request dict as will be sent in the batch
        :rtype: dict[str, Any]
        """
        return self.request(
            id=id, method="PUT", url=url, body=body, headers=headers, params=params
        )

    def delete(
        self, id: str, url: str, *, headers: dict = {}, params: dict = {}
    ) -> dict[str, Any]:
        """
        Add a DELETE request to the batch

        :param id: The ID of the request
        :type id: str
        :param url: The URL to request
        :type url: str
        :param params: The query parameters to send, defaults to {}
        :type params: dict, optional
        :param headers: The headers to send in the request, defaults to {}
        :type headers: dict, optional
        :return: The request dict as will be sent in the batch
        :rtype: dict[str, Any]
        """
        return self.request(
            id=id, method="DELETE", url=url, params=params, headers=headers
        )

    def split_requests(self):
        chunk = []
        for key in self:
            chunk.append(key)
            if len(chunk) == self.max_batch_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

    def as_request(self, keys, encode_marques=False):
        reqs = []
        for key in keys:
            item = self[key]
            reqs.append(item)
        return {"requests": reqs}

    def send(self):
        """
        Send the batch request
        """

        headers = {"Accept": "application/json"}
        if self.isolation_snapshot:
            headers["Isolation"] = "snapshot"
        if self.continue_on_error:
            headers["Prefer"] = "odata.continue-on-error"

        for keys in self.split_requests():
            requests = self.as_request(keys, encode_marques=True)
            response = self.session.post(self.batch_url, json=requests, headers=headers)
            self.responses.append(response)

        return ODataBatchResponse(self.responses, self)


class ODataBatchResponse(dict):
    def __init__(self, responses, request):
        self.request = request
        self.responses = responses

        for response in responses:
            resptext = response.text
            # remove random UTF8 BOMs that BC can add if response is a number
            resptext = resptext.replace("\ufeff", "")
            for resp in json.loads(resptext)["responses"]:
                self[resp["id"]] = resp
        return super().__init__()

    def errors(self) -> dict:
        """
        Get all the responses that returned an error

        :return: A dictionary of all the responses that returned an error
        :rtype: dict
        """
        return dict(
            (key, value) for key, value in self.items() if value["status"] >= 300
        )
