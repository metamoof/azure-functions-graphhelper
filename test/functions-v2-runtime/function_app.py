import logging

import azure.functions as func
from azure.identity import DefaultAzureCredential
from msgraphhelper.subscriptions import (
    ChangeNotification,
    ChangeNotificationHandlerResponse,
    SubscriptionServiceBlueprint,
    graph_endpoint,
    graph_scope,
)

http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
http_logger.setLevel(logging.WARNING)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

bp = SubscriptionServiceBlueprint(
    endpoint=graph_endpoint,
    credential=DefaultAzureCredential(),
    scopes=[graph_scope],
)


# @bp.subscribe(changetype="updated", resource="me")
# def handle_me_update(notification: dict) -> None:
#     logging.info(f"Received a notification for me: {notification}")


# @bp.subscribe(
#     changetype=["created", "updated"],
#     resource="users/eea67ca9-d5b9-4079-8519-f012b3467c19/chats/getAllMessages",
# )
# def handle_chat_message(notification: dict) -> None:
#     logging.info(f"Received a notification for a chat message: {notification}")


@bp.subscribe(
    changetype=["updated"],
    resource="drives/b!ANCjyRrvbEywxgNKNnvIygI1PL5lZMRHlSGwBv0B2pEchQwIKtPiT55IfOA5-r6z/root",
)
def handle_drive_item(
    notification: ChangeNotification,
) -> ChangeNotificationHandlerResponse:
    logging.info(f"Received a notification for a drive item: {notification}")
    return {"status_code": 200, "body": "OK"}


app.register_blueprint(bp)
