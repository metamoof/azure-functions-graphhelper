import datetime
import hmac
import logging
import os
import secrets
import urllib.parse
from hashlib import sha256
from re import T, sub

import requests
from azure import functions
from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.data.tables import TableClient, TableServiceClient
from azure.identity import DefaultAzureCredential
from typing_extensions import (
    Callable,
    List,
    Literal,
    NotRequired,
    Optional,
    Required,
    TypedDict,
)

from .session import get_graph_session

ChangeType = Literal["created", "updated", "deleted"]


Subscription = TypedDict(
    "Subscription",
    {
        "@odata.type": str,
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


SubscriptionNotification = TypedDict(
    "SubscriptionNotification",
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

SubscriptionNotificationCollection = TypedDict(
    "SubscriptionNotificationCollection",
    {
        "@odata.type": Literal["#microsoft.graph.changeNotificationCollection"],
        "validationTokens": NotRequired[list[str]],
        "value": list[SubscriptionNotification],
    },
)

TableServiceSubscription = TypedDict(
    "TableServiceSubscription",
    {
        "PartitionKey": str,  # the endpoint
        "RowKey": str,  # changeType-resource
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


class SubscriptionServiceBlueprint(functions.Blueprint):
    def __init__(
        self,
        endpoint: str,
        credential: TokenCredential,
        scopes: List[str],
        table_service_connection_string: str = os.environ["AzureWebJobsStorage"],
        table_service_name: str = "subscriptionHelper",
        expiration_duration: datetime.timedelta = datetime.timedelta(days=3),
        expiration_tolerance: datetime.timedelta = datetime.timedelta(hours=36),
        notification_url: Optional[str] = None,
        **kwargs,
    ):

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
        self.route(
            "subscriptions/handler",
            methods=["POST"],
            auth_level=functions.AuthLevel.ANONYMOUS,
        )(self.handle_notification)
        self.schedule(
            schedule="0 0 0 * * *",
            arg_name="myTimer",
            run_on_startup=True,
            use_monitor=False,
        )(self.timer_trigger)

    def _init_tables_store(self):
        logging.info(
            f"Subscription service is connecting to Table Service with connection string {self.table_service_connection_string}"
        )
        table_service = TableServiceClient.from_connection_string(
            os.environ["AzureWebJobsStorage"]
        )
        table = table_service.create_table_if_not_exists(self.table_service_name)

    def _get_notification_url(self) -> str:
        if "SubscriptionsHelperURL" in os.environ:
            return os.environ["SubscriptionsHelperURL"]
        return f"{os.environ['WEBSITE_HOSTNAME']}/subscriptions/handler"

    def _get_table_client(self) -> TableClient:
        return TableClient.from_connection_string(
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
        [Callable[[SubscriptionNotification], None]],
        Callable[[SubscriptionNotification], None],
    ]:
        if isinstance(changetype, list):
            changes = ",".join(changetype)
        else:
            changes = changetype

        def wrapper(
            f: Callable[[SubscriptionNotification], None]
        ) -> Callable[[SubscriptionNotification], None]:
            self.subscriptions[f"{changes}-{resource}"] = f
            return f

        return wrapper

    def update_subscriptions(self):  # This needs to be done in a Singleton
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
                    del subscription["recreate"]
                elif subscription.get("refresh"):
                    logging.info(f"Subscription {key} marked for refresh")
                    subscriptions_for_refresh.append(subscription)
                    del subscription["refresh"]
                else:
                    logging.info(f"Subscription {key} is valid and up to date")
                    self.client_states[subscription["clientState"]] = (
                        self.subscriptions[key]
                    )
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
                table.upsert_entity(entity=newsub)
            else:
                logging.error(
                    f"Failed to create subscription for {subscription['resource']} with error {response.status_code}, {response.text}"
                )

    def set_validation_token(self, client_state: str, token: str) -> None:
        self.validation_tokens[client_state] = token

    def handle_notification(
        self, req: functions.HttpRequest, context: functions.Context
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
                # if notification["@odata.type"] == "#microsoft.graph.changeNotification":
                if "value" not in notifications:
                    notifications = {"value": [notifications]}
                for notification in notifications["value"]:
                    if "lifecycleEvent" in notification:
                        if notification["lifecycleEvent"] == "subscriptionRemoved":
                            logging.info(
                                f"Subscription {notification['subscriptionId']} removed"
                            )
                            table = self._get_table_client()
                            row_key = sha256(
                                f"{notification['changeType']}-{notification['resource']}".encode()
                            ).hexdigest()
                            subscription: TableServiceSubscription = table.get_entity(partition_key=self.partition_key, row_key=row_key)  # type: ignore
                            subscription["recreate"] = True
                            table.upsert_entity(entity=subscription)
                            self.update_subscriptions()
                            return functions.HttpResponse(
                                status_code=202, headers={"Content-Type": "text/plain"}
                            )
                        elif (
                            notification["lifecycleEvent"] == "reauthorizationRequired"
                        ):
                            logging.info(
                                f"Subscription {notification['subscriptionId']} removed"
                            )
                            table = self._get_table_client()
                            row_key = sha256(
                                f"{notification['changeType']}-{notification['resource']}".encode()
                            ).hexdigest()
                            subscription: TableServiceSubscription = table.get_entity(partition_key=self.partition_key, row_key=row_key)  # type: ignore
                            subscription["refresh"] = True
                            table.upsert_entity(entity=subscription)
                            self.update_subscriptions()
                            return functions.HttpResponse(
                                status_code=202, headers={"Content-Type": "text/plain"}
                            )
                        else:
                            return functions.HttpResponse(
                                status_code=400, headers={"Content-Type": "text/plain"}
                            )
                        # Need to handle missed notifications!
                    elif notification["clientState"] in self.client_states:
                        logging.info(
                            f"Executing function {self.client_states[notification['clientState']].__name__}"
                        )
                        self.client_states[notification["clientState"]](
                            notification
                        )  # this needs putting in an orchestrator
                        return functions.HttpResponse(
                            status_code=200, headers={"Content-Type": "text/plain"}
                        )
                    else:
                        return functions.HttpResponse(
                            status_code=404, headers={"Content-Type": "text/plain"}
                        )

            except ValueError:
                return functions.HttpResponse(
                    status_code=400, headers={"Content-Type": "text/plain"}
                )

    def timer_trigger(self, myTimer: functions.TimerRequest) -> None:
        if myTimer.past_due:
            logging.info("The timer is past due!")
        self.update_subscriptions()


graph_endpoint = "https://graph.microsoft.com/v1.0/subscriptions/"
graph_scope = "https://graph.microsoft.com/.default"
