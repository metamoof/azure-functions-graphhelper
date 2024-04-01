"""Azure Functions BaseURL

Try to work out the current base url of an azure functions instance without
using an HTTP trigger.
"""

import json
import os
from email.mime import base
from pathlib import Path


def get_baseurl(
    host_path: str = "host.json",
    local_settings_path: str = "local.settings.json",
):

    # Configuration file paths
    hostconfig = Path(host_path)
    local_settings = Path(local_settings_path)

    # First, determine if https. Assume https if not running in a development environment

    # Azure Functions Core Tools sets this setting to "Development"

    protocol = (
        "http"
        if os.environ.get("AZURE_FUNCTIONS_ENVIRONMENT") == "Development"
        else "https"
    )

    # Next, determine the hostname. This is set by the Azure App service runtime

    hostname = os.environ.get("WEBSITE_HOSTNAME")

    if hostname is None:  # We are probably running outside of a function app runtime
        host = "localhost"
        port = "7071"

        if (
            local_settings.exists()
            and os.environ.get("AZURE_FUNCTIONS_ENVIRONMENT") == "Development"
        ):
            with local_settings.open() as f:
                settings = json.load(f)
                if "Host" in settings and "LocalHttpPort" in settings["Host"]:
                    port = settings["Host"]["LocalHttpPort"]
        hostname = f"{host}:{port}"

    # Finally, determine the route prefix. This is set in the host.json file

    route_prefix = "api"

    if hostconfig.exists():
        with hostconfig.open() as f:
            settings = json.load(f)
            if (
                "extensions" in settings
                and "http" in settings["extensions"]
                and "routePrefix" in settings["extensions"]["http"]
            ):
                route_prefix = settings["extensions"]["http"]["routePrefix"]

    # Combine the parts into a base url

    baseurl = f"{protocol}://{hostname}/{route_prefix}"

    return baseurl


baseurl = get_baseurl()
