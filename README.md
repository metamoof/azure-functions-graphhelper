# MSGraphHelper - Handle MS Graph Change Notifications in a Pythonic manner in Azure Functions

Handling Change Notifications in Microsoft Graph, along with its subscriptions and lifecycle notifications is quite complex, but it's all repetitive boilerplate. This library deals with many of the standard complexities, making it easy to just create functions that will handle specific change notifications, with just a decorator that indicates what they should subscribe to.

This is a library for use in Azure Functions Python v2 applications. Currently Azure functions Python v1 is not supported.

This library is still in active development, considered in alpha stage, and doesn't yet support 100% of the Graph Change Notifications API.

## Quick Start

Create a Python v2 Azure functions project. Put this into `function_app.py`

```python
import azure.functions as func
from azure.identity import DefaultAzureCredential
import logging
from msgraphhelper.subscriptions import (
    ChangeNotification,
    ChangeNotificationHandlerResponse,
    SubscriptionServiceBlueprint,
    graph_endpoint,
    graph_scope,
)

# Create your standard Function App
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Create a Subscription Blueprint
bp = SubscriptionServiceBlueprint(
    endpoint=graph_endpoint, # https://graph.microsoft.com/v1.0/subscriptions/
    credential=DefaultAzureCredential(),
    scopes=[graph_scope], # https://graph.microsoft.com/.default
)

# Create a Change Notification Handler, and subscribe to changes for https://graph.microsoft.com/v1.0/me
@bp.subscribe(changetype="updated", resource="me")
def handle_me_update(notification: ChangeNotification) -> ChangeNotificationHandlerResponse:
    logging.info(f"Received a notification for an update to me: {notification}")
    return "OK"

app.register_blueprint(bp)
```

This file will:

- Contact the MS Graph API and create a subscription to updates for the resource https://graph.microsoft.com/v1.0/me
- Handle the [automatic verification step](https://learn.microsoft.com/en-us/graph/change-notifications-delivery-webhooks?tabs=http#notificationurl-validation) of the subscription
- Automatically [renew](https://learn.microsoft.com/en-us/graph/change-notifications-delivery-webhooks?tabs=http#renew-a-subscription) and recreate the subscription if it has expired
- Handle the [`reauthorisationRequired`](https://learn.microsoft.com/en-us/graph/change-notifications-lifecycle-events?tabs=http#responding-to-reauthorizationrequired-notifications) and [`subscriptionRemoved`](https://learn.microsoft.com/en-us/graph/change-notifications-lifecycle-events?tabs=http#responding-to-subscriptionremoved-notifications) lifeycle notifications. (Currently, the `missed` lifecycle notification is not handled, but [it's on the roadmap](https://github.com/metamoof/azure-functions-graphhelper/issues/2))
- Receive notifications for all subscribed resources, and then send them, one at a time to the `handle_me_update` function. This means that each individual notification will get its own execution of the function.

## Behind the scenes

The `SubscriptionServiceBlueprint` is a subclass of `azure.durable_functions.Blueprint`, so it supports all the standard triggers and decorators that the Python v2 Durable Functions Blueprint does. You can then register that blueprint with any `azure.functions.FunctionApp` or `azure.durable-functions.DFApp` instance in your root `function_app.py` file.

It creates a table to store the subscription information in an azure table storage service. By default it will use the table storage service provided by the `AzureWebJobsStorage` environment variable, and is compatible with `UseDevelopmentStorage=True` and thus Azurite table storage in local development. You can specify a different table storage connection string by specifying `table_service_connection_string` in the `SubscriptionServiceBlueprint.__init__` constructor. You can also change the name of the table it creates by specifying `table_service_name`. It defaults to `subscripionHelper`.

When you use the `subscribe` decorator, this will create a record within the `SubscriptionServiceBlueprint` of that function and the resource and type of update it subscribes to. It will also declare that handler as a [Durable Functions Activity Function](https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-types-features-overview#activity-functions), which returns a `ChangeNotificationHandlerResponse`, basically anything serialisable as JSON. It cannot return `None`. You don't need to know how to write Durable Functions in order to use this library, just be aware that anything returned is serialised to JSON. If you are unable to handle the notification and wish to return an error, then just raise an exception, and this will be interpreted as an error by the calling function.

The URL supplied by the `SubscriptionServiceBlueprint` for the subscription is calculated based on environment variables (e.g. `WEBSITE_HOSTNAME`) and functions app configuration. It can be overriden by setting the `SubscriptionsHelperURL` environment variable, which is useful when the call must be through an API Manager, or to set the URL used when debveloping locally using an `ngrok` tunnel or similar. The default endpoint is `/api/subscriptions/handler`, so if you're using an ngrok tunnel called `ostrich-left-fish` then the full URL should be `https://ostrich-left-fish.ngrok-free.app/api/subscriptions/handler`, and this can be set by adding `"SubscriptionsHelperURL": "https://ostrich-left-fish.ngrok-free.app/api/subscriptions/handler"` in your `local.settings.json` file. If you want an example of using ngrok with azure functions, Microsoft has [this tutorial on local development for an event grid trigger](https://learn.microsoft.com/en-us/azure/azure-functions/functions-event-grid-blob-trigger?tabs=isolated-process%2Cnodejs-v4&pivots=programming-language-python) that gives you another idea of how to use it.

The `SubscriptionServiceBlueprint` includes a TimerTrigger that is executed on startup and every hour in order to create and update the subscriptions. This updater will check its database to see whether any subscriptions need creating or refreshing. New subscriptions will be created with an expiration date of 3 days from now, this can be altered by passing a `datetime.duration` instance to the `expiration_duration` parameter of the `SubscriptionServiceBlueprint.__init__` constructor. It will also automatically [renew](https://learn.microsoft.com/en-us/graph/change-notifications-delivery-webhooks?tabs=http#renew-a-subscription) any subscription that expires less than 36 hours from the time of checking, and this can be altered by passing a `datetime.duration` instance to the `expiration_tolerance` parameter of the `SubscriptionServiceBlueprint.__init__` constructor. If a subscription existed, but is expired, then it will be recreated as new. This function will also update or recreate subscriptions that have been marked as [`reauthorisationRequired`](https://learn.microsoft.com/en-us/graph/change-notifications-lifecycle-events?tabs=http#responding-to-reauthorizationrequired-notifications) or [`subscriptionRemoved`](https://learn.microsoft.com/en-us/graph/change-notifications-lifecycle-events?tabs=http#responding-to-subscriptionremoved-notifications) using lifecycle notifications.

This library makes heavy use of the Durable Functions programming paradigm:

- The `SubscriptionServiceBlueprint` will update its subscriptions inside of a [Singleton instance](https://learn.microsoft.com/en-us/azure/azure-functions/durable/durable-functions-singletons?tabs=python)
- The notifications handler will spin up a `change_notification_handler_orchestrator` for each notification, which will call your handler activity for each individual notification.

## Security Considerations

The `SubscriptionServiceBlueprint` handler endpoint is currently declared with `auth_level=AuthLevel.ANONYMOUS`, which means everybody in the world can spam it. Every subscription is created with a random token produced by [`secrets.token_urlsafe(64)`](https://docs.python.org/3/library/secrets.html#secrets.token_urlsafe), and MS Graph will send this token back to authenticate every notification. The handler endpoint will error if that token is not found, or there is no function associated with that secret. This token is passed on in the `ChangeNotification` object, so it will be seen by the handler, and it's also available to be read by any function or person with access to the table storage service used by the library.

This does mean we are bypassing the azure functions security model, and can lead to performance issues, as functions automatically rejects function calls that don't carry the correct token when function authentication is used. I have an [open issue](https://github.com/metamoof/azure-functions-graphhelper/issues/9) to allow that security model to be used additionally to the above check. I don't currently have plans to support OAuth based models for authentication, as I believe Graph itself has no way to specify it.

## Logging

The table storage library does create a certain amount of noise in the logging system, the only way I have found to mute it is by adding this to the `function_app.py`:

```python
import logging

http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
http_logger.setLevel(logging.WARNING) # or logging.ERROR
```

but this will stop all the Microsoft Azure SDK libraries from emitting HTTP logs, which you may need for other reasons.

I have an [open issue](https://github.com/metamoof/azure-functions-graphhelper/issues/4) to add proper logging control to this library, so you can choose to suppress the logs.

# Accessing the Graph API

This library also includes a helper to access the MS Graph API using a [`requests.Session`](https://docs.python-requests.org/en/latest/user/advanced/#session-objects) object.

```python

from msgraphhelper import AzureIdentityCredentialAdapter, get_graph_session, get_default_graph_session, graph_scope
from azure.identity import InteractiveBrowserCredential, DefaultAzureCredential
import requests

# get a session to msgraph using default settings and an azure.identity.DefaultAzureCredential
default_session = get_default_graph_session()
default_response = default_session.get("https://graph.microsoft.com/v1.0/")
# response is a requests.HttpResponse and contains a list of all possible enpoints

# get a session by asking the user to log into the browser and the Business Central scope
bc_credentials = InteractiveBrowserCredential()
bc_scope = "https://api.businesscentral.dynamics.com/.default"
bc_session = get_graph_session(bc_credentials, bc_scope)
bc_respose = bc_session.get("http://api.businesscentral.dynamics.com/environments/v1.1")
# response is a requests.HttpResponse that contains a list of all the business central
# environments the browser user has access to

# construct an authenticated session from scratch. It's the equivalent of get_default_graph_session
req_credentials = DefaultAzureCredential()
authenticator = AzureIdentityCredentialAdapter(req_credentials, graph_scope)
req_session = requests.session()
req_session.auth = authenticator
req_response = req_session.get("https://graph.microsoft.com/v1.0/")
# response is a requests.HttpResponse and contains a list of all possible enpoints
```
