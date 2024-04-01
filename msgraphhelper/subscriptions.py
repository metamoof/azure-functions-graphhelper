import datetime
import functools
import logging
import os
import secrets
from hashlib import sha256
from hmac import new

import requests
from azure import functions
from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.data.tables import TableClient, TableServiceClient
from azure.data.tables.aio import TableClient as AsyncTableClient
from azure.durable_functions import (
    Blueprint,
    DurableOrchestrationClient,
    DurableOrchestrationContext,
    OrchestrationRuntimeStatus,
)
from azure.identity import DefaultAzureCredential
from typing_extensions import (
    Callable,
    List,
    Literal,
    NotRequired,
    Optional,
    Required,
    TypedDict,
    Union,
)

from .session import get_graph_session, graph_scope
from .url import baseurl

ChangeType = Literal["created", "updated", "deleted"]

Subscription = TypedDict(
    "Subscription",
    {
        "@odata.type": NotRequired[Literal["#microsoft.graph.subscription"]],
        "applicationId": str,
        "changeType": ChangeType,
        "clientState": str,
        "creatorId": str,
        "encryptionCertificate": str,
        "encryptionCertificateId": str,
        "expirationDateTime": str,
        "id": str,
        "includeResourceData": str,
        "latestSupportedTlsVersion": str,
        "lifecycleNotificationUrl": str,
        "notificationQueryOptions": str,
        "notificationUrl": str,
        "notificationUrlAppId": str,
    },
)

SubscriptionRequest = TypedDict(
    "SubscriptionRequest",
    {
        "changeType": str,  # Can be a single ChangeType or a comma-separated list of ChangeType
        "notificationUrl": str,
        "lifecycleNotificationUrl": NotRequired[str],
        "resource": str,
        "expirationDateTime": str,
        "clientState": NotRequired[str],
        "latestSupportedTlsVersion": NotRequired[Literal["v1_2"]],
        "includeResourceData": NotRequired[bool],
    },
)


ChangeNotification = TypedDict(
    "ChangeNotification",
    {
        "@odata.type": Required[Literal["#microsoft.graph.changeNotification"]],
        "changeType": Required[ChangeType],
        "clientState": str,
        "encryptedContent": dict,
        "id": str,
        "lifecycleEvent": Literal[
            "missed", "subscriptionRemoved", "reauthorizationRequired"
        ],
        "resource": Required[str],
        "resourceData": dict,
        "subscriptionExpirationDateTime": Required[str],
        "subscriptionId": Required[str],
        "tenantId": Required[str],
    },
)

ChangeNotificationCollection = TypedDict(
    "ChangeNotificationCollection",
    {
        "@odata.type": Literal["#microsoft.graph.changeNotificationCollection"],
        "validationTokens": NotRequired[list[str]],
        "value": list[ChangeNotification],
    },
)

TableServiceSubscription = TypedDict(
    "TableServiceSubscription",
    {
        "PartitionKey": str,  # sha256 of the endpoint
        "RowKey": str,  # sha256 of changeType-resource
        "changeType": ChangeType,
        "resource": str,
        "expirationDateTime": str,
        "subscriptionId": NotRequired[str],
        "validationToken": NotRequired[str],
        "clientState": str,
        "recreate": NotRequired[bool],
        "refresh": NotRequired[bool],
    },
)

FunctionHandlerInput = TypedDict(
    "FunctionHandlerInput",
    {
        "function_name": str,
        "change_notification": ChangeNotification,
    },
)


ChangeNotificationHandlerResponse = Union[dict, str, int, list, float, bool]

ChangeNotificationHandler = Callable[
    [ChangeNotification], ChangeNotificationHandlerResponse
]


class SubscriptionServiceBlueprint(Blueprint):
    def __init__(
        self,
        endpoint: str,
        credential: TokenCredential,
        scopes: List[str],
        table_service_connection_string: str | None = None,
        table_service_name: str = "subscriptionHelper",
        expiration_duration: datetime.timedelta = datetime.timedelta(days=3),
        expiration_tolerance: datetime.timedelta = datetime.timedelta(hours=36),
        notification_url: Optional[str] = None,
        **kwargs,
    ):
        if table_service_connection_string is None:
            table_service_connection_string = os.environ["AzureWebJobsStorage"]
        self.endpoint = endpoint
        if not self.endpoint.endswith("/"):
            self.endpoint += "/"
        self.credentials = credential
        self.scopes = scopes
        self.table_service_connection_string = table_service_connection_string
        self.table_service_name = table_service_name
        self.expiration_duration = expiration_duration
        self.expiration_tolerance = expiration_tolerance

        if notification_url:
            self._notification_url = notification_url
        else:
            self._notification_url = self._get_notification_url()
        self._init_tables_store()
        self.subscriptions = {}
        self.client_states = {}
        self.validation_tokens = {}
        self.partition_key = sha256(self.endpoint.encode()).hexdigest()
        super().__init__(**kwargs)
        self._add_bindings()

    def _add_bindings(self):
        self.route(
            "subscriptions/handler",
            methods=["POST"],
            auth_level=functions.AuthLevel.ANONYMOUS,
        )(self.durable_client_input(client_name="client")(self.handle_notification))
        self.schedule(
            schedule="0 0 0 * * *",
            arg_name="myTimer",
            run_on_startup=True,
            use_monitor=False,
        )(self.durable_client_input(client_name="client")(self.timer_trigger))
        self.orchestration_trigger(context_name="context")(
            self.update_subscriptions_orchestration
        )
        self.activity_trigger(input_name="input")(self.update_subscriptions_activity)
        self.orchestration_trigger(context_name="context")(
            self.change_notification_handler_orchestrator
        )

    def _init_tables_store(self):
        logging.info(
            f"Subscription service is connecting to Table Service with connection string {self.table_service_connection_string}"
        )
        table_service = TableServiceClient.from_connection_string(
            os.environ["AzureWebJobsStorage"]
        )
        table = table_service.create_table_if_not_exists(self.table_service_name)

    def _get_notification_url(self) -> str:
        # If we set the URL in the environment, use that
        if "SubscriptionsHelperURL" in os.environ:
            return os.environ["SubscriptionsHelperURL"]
        # Otherwise, use the default, based on the calculation in url.py
        # should default roughly to https://{WEBSITE_HOSTNAME}/api/subscriptions/handler
        return f"{baseurl}/subscriptions/handler"

    def _get_table_client(self) -> TableClient:
        return TableClient.from_connection_string(
            conn_str=self.table_service_connection_string,
            table_name=self.table_service_name,
        )

    def _get_table_client_async(self) -> AsyncTableClient:
        return AsyncTableClient.from_connection_string(
            conn_str=self.table_service_connection_string,
            table_name=self.table_service_name,
        )

    def get_session(self) -> requests.Session:
        return get_graph_session(self.credentials, *self.scopes)

    def get_subscription(self, subscription_id: str) -> dict:
        response = self.get_session().get(f"{self.endpoint}/{subscription_id}")
        response.raise_for_status()
        return response.json()

    def subscribe(
        self, changetype: ChangeType | List[ChangeType], resource: str
    ) -> Callable[
        [ChangeNotificationHandler],
        ChangeNotificationHandler,
    ]:
        if isinstance(changetype, list):
            changes = ",".join(changetype)
        else:
            changes = changetype

        def wrapper(f: ChangeNotificationHandler) -> ChangeNotificationHandler:
            self.subscriptions[f"{changes}-{resource}"] = f.__name__

            @self.activity_trigger(input_name="notification")
            @functools.wraps(f)
            def wrapped_notification_handler(
                notification: ChangeNotification,
            ) -> ChangeNotificationHandlerResponse:
                return f(notification)

            return wrapped_notification_handler

        return wrapper

    async def update_subscriptions(self, client: DurableOrchestrationClient) -> None:
        instance_id = f"update_subscriptions_{self.partition_key}"
        existing_instance = await client.get_status(instance_id=instance_id)
        if existing_instance.runtime_status in [
            OrchestrationRuntimeStatus.Completed,
            OrchestrationRuntimeStatus.Failed,
            OrchestrationRuntimeStatus.Terminated,
            None,
        ]:
            logging.info(f"Starting new instance of update_subscriptions")
            instance_id = await client.start_new(
                "update_subscriptions_orchestration", instance_id=instance_id
            )
        else:
            logging.info(
                f"Instance of update_subscriptions already running, not repeating"
            )

    def update_subscriptions_orchestration(self, context: DurableOrchestrationContext):
        yield context.call_activity("update_subscriptions_activity")

    def update_subscriptions_activity(
        self, input: str
    ):  # This needs to be done in a Singleton
        table = self._get_table_client()
        subscriptions_for_creation = []
        subscriptions_for_refresh = []
        now = datetime.datetime.utcnow().isoformat() + "Z"
        expiration_tolerance_dt = datetime.datetime.utcnow() + self.expiration_tolerance
        expiration_tolerance = expiration_tolerance_dt.isoformat() + "Z"
        new_expiration_dt = datetime.datetime.utcnow() + self.expiration_duration
        new_expiration = new_expiration_dt.isoformat() + "Z"
        session = self.get_session()
        for key in self.subscriptions:
            row_key = sha256(key.encode()).hexdigest()
            try:
                subscription: TableServiceSubscription = table.get_entity(partition_key=self.partition_key, row_key=row_key)  # type: ignore
                if subscription.get("subscriptionId") is None:
                    logging.info(f"Subscription {key} has no subscriptionId")
                    subscription["expirationDateTime"] = new_expiration
                    subscriptions_for_creation.append(subscription)
                elif subscription["expirationDateTime"] <= now:
                    logging.info(f"Subscription {key} has expired")
                    subscription["expirationDateTime"] = new_expiration
                    subscriptions_for_creation.append(subscription)
                elif subscription["expirationDateTime"] <= expiration_tolerance:
                    subscriptions_for_refresh.append(subscription)
                elif subscription.get("recreate"):
                    logging.info(f"Subscription {key} marked for recreation")
                    subscription["expirationDateTime"] = new_expiration
                    subscriptions_for_creation.append(subscription)
                elif subscription.get("refresh"):
                    logging.info(f"Subscription {key} marked for refresh")
                    subscriptions_for_refresh.append(subscription)
                else:
                    logging.info(f"Subscription {key} is valid and up to date")
                self.client_states[subscription["clientState"]] = self.subscriptions[
                    key
                ]
            except HttpResponseError as e:
                if e.status_code == 404:
                    logging.info(f"Subscription {key} not found in the table")
                    subscription: TableServiceSubscription = {
                        "PartitionKey": self.partition_key,
                        "RowKey": row_key,
                        "changeType": key.split("-", 1)[0],
                        "resource": key.split("-", 1)[1],
                        "expirationDateTime": new_expiration,
                        "clientState": secrets.token_urlsafe(64),
                    }
                    table.upsert_entity(entity=subscription)
                    self.client_states[subscription["clientState"]] = (
                        self.subscriptions[key]
                    )
                    subscriptions_for_creation.append(subscription)
                else:
                    raise e

        for subscription in subscriptions_for_refresh:
            logging.info(f"Refreshing subscription {subscription['changeType']}-{subscription['resource']} {subscription['subscriptionId']}")  # type: ignore
            new_expiration_dt = datetime.datetime.utcnow() + self.expiration_duration
            new_expiration = new_expiration_dt.isoformat() + "Z"
            response = session.patch(
                f"{self.endpoint}/{subscription['subscriptionId']}",  # type: ignore
                json={"expirationDateTime": new_expiration},
            )
            if response.status_code == 200:
                newsub = table.get_entity(
                    partition_key=self.endpoint, row_key=subscription["RowKey"]
                )
                newsub["expirationDateTime"] = new_expiration
                newsub["refresh"] = False
                table.upsert_entity(entity=newsub)
            else:
                logging.error(
                    f"Failed to refresh subscription {subscription['subscriptionId']} with error {response.status_code}, {response.text}"  # type: ignore
                )

        for subscription in subscriptions_for_creation:
            logging.info(
                f"Creating subscription for {subscription['changeType']}-{subscription['resource']}"
            )
            table.upsert_entity(entity=subscription)
            request: SubscriptionRequest = {
                "changeType": subscription["changeType"],
                "notificationUrl": self._notification_url,
                "lifecycleNotificationUrl": self._notification_url,
                "resource": subscription["resource"],
                "expirationDateTime": subscription["expirationDateTime"],
                "clientState": subscription["clientState"],
            }
            logging.info(f"Request: {request}")
            response = session.post(
                self.endpoint,
                json=request,
            )

            if response.status_code == 201:
                newsub = table.get_entity(
                    partition_key=self.partition_key, row_key=subscription["RowKey"]
                )
                logging.info(f"Subscription created: {response.json()}")
                logging.info(f"Received headers: {response.headers}")
                newsub["subscriptionId"] = response.json()["id"]
                newsub["recreate"] = False
                table.upsert_entity(entity=newsub)
            else:
                logging.error(
                    f"Failed to create subscription for {subscription['resource']} with error {response.status_code}, {response.text}"
                )

    def set_validation_token(self, client_state: str, token: str) -> None:
        self.validation_tokens[client_state] = token

    async def handle_notification(
        self,
        req: functions.HttpRequest,
        context: functions.Context,
        client: DurableOrchestrationClient,
    ) -> functions.HttpResponse:
        logging.info("Handling a Subscripion notification")
        logging.info(f"Request Params: {req.params}")
        logging.info(f"Request Body: {req.get_body()}")
        params = req.params
        # First check if it's a validation request
        if "validationToken" in params:
            # if req.params["clientState"] in self.client_states:
            body = params["validationToken"]
            resp = functions.HttpResponse(
                body=body, status_code=200, headers={"Content-Type": "text/plain"}
            )
            # self.set_validation_token(
            #     params["clientState"], params["validationToken"]
            # )
            logging.info(f"Returning validation token {body}")
            return resp
        else:
            try:
                notifications = req.get_json()
                if "value" not in notifications:
                    notifications = {"value": [notifications]}
                for notification in notifications["value"]:
                    if "lifecycleEvent" in notification:
                        if notification["lifecycleEvent"] == "subscriptionRemoved":
                            logging.info(
                                f"Subscription {notification['subscriptionId']} removed"
                            )
                            table = self._get_table_client_async()
                            row_key = sha256(
                                f"{notification['changeType']}-{notification['resource']}".encode()
                            ).hexdigest()
                            subscription: TableServiceSubscription = table.get_entity(partition_key=self.partition_key, row_key=row_key)  # type: ignore
                            subscription["recreate"] = True
                            await table.upsert_entity(entity=subscription)
                            await self.update_subscriptions(client)
                            return functions.HttpResponse(
                                status_code=202, headers={"Content-Type": "text/plain"}
                            )
                        elif (
                            notification["lifecycleEvent"] == "reauthorizationRequired"
                        ):
                            logging.info(
                                f"Subscription {notification['subscriptionId']} removed"
                            )
                            table = self._get_table_client_async()
                            row_key = sha256(
                                f"{notification['changeType']}-{notification['resource']}".encode()
                            ).hexdigest()
                            subscription: TableServiceSubscription = table.get_entity(partition_key=self.partition_key, row_key=row_key)  # type: ignore
                            subscription["refresh"] = True
                            await table.upsert_entity(entity=subscription)
                            await self.update_subscriptions(client)
                            return functions.HttpResponse(
                                status_code=202, headers={"Content-Type": "text/plain"}
                            )
                        else:
                            return functions.HttpResponse(
                                status_code=400, headers={"Content-Type": "text/plain"}
                            )
                        # Need to handle missed notifications!
                    elif notification["clientState"] in self.client_states:
                        func = self.client_states[notification["clientState"]]
                        logging.info(f"Executing function {func}")
                        funcinput = {
                            "function_name": func,
                            "change_notification": notification,
                        }

                        instance_id = await client.start_new(
                            orchestration_function_name="change_notification_handler_orchestrator",
                            instance_id=None,
                            client_input=funcinput,
                        )

                        return client.create_check_status_response(
                            request=req, instance_id=instance_id
                        )
                    else:
                        return functions.HttpResponse(
                            status_code=404, headers={"Content-Type": "text/plain"}
                        )

            except ValueError:
                return functions.HttpResponse(
                    status_code=400, headers={"Content-Type": "text/plain"}
                )

            return functions.HttpResponse(
                status_code=400, headers={"Content-Type": "text/plain"}
            )

    async def timer_trigger(
        self, myTimer: functions.TimerRequest, client: DurableOrchestrationClient
    ) -> None:
        if myTimer.past_due:
            logging.info("The timer is past due!")
        await self.update_subscriptions(client)

    def change_notification_handler_orchestrator(
        self, context: DurableOrchestrationContext
    ):
        input: FunctionHandlerInput = context.get_input()  # type: ignore
        response: ChangeNotificationHandlerResponse = yield context.call_activity(
            name=input["function_name"], input_=input["change_notification"]
        )
        return response


graph_endpoint = "https://graph.microsoft.com/v1.0/subscriptions/"
