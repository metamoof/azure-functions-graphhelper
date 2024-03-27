# from https://github.com/Azure/azure-sdk-for-python/blob/main/sdk/core/azure-core/CLIENT_LIBRARY_DEVELOPER.md
# %%

from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import (
    BearerTokenCredentialPolicy,
    ContentDecodePolicy,
    HeadersPolicy,
    NetworkTraceLoggingPolicy,
    ProxyPolicy,
    RedirectPolicy,
    RetryPolicy,
    UserAgentPolicy,
)
from azure.core.pipeline.transport import RequestsTransport
from azure.core.rest import HttpRequest


class FooServiceClient:

    def __init__(self, credential, scopes, **kwargs):
        transport = kwargs.get("transport", RequestsTransport(**kwargs))
        policies = [
            kwargs.get(
                "authentication_policy",
                BearerTokenCredentialPolicy(credential, *scopes),
            ),
            kwargs.get("redirect_policy", RedirectPolicy(**kwargs)),
        ]
        self._pipeline = Pipeline(transport, policies=policies)

    def get_foo_properties(self, endpoint, **kwargs):
        # Create a generic HTTP Request. This is not specific to any particular transport
        # or pipeline configuration.
        new_request = HttpRequest("GET", url=endpoint)

        response = self._pipeline.run(new_request, **kwargs)
        return response.http_response


from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential

creds = InteractiveBrowserCredential()
endpoint = "https://graph.microsoft.com/"

client = FooServiceClient(
    credential=creds, endpoint=endpoint, scopes=["https://graph.microsoft.com/.default"]
)

# %%
