# scanner/check_function_apps.py
# Detect Azure Function Apps that allow anonymous access or lack authentication.

from azure.identity import ClientSecretCredential
from azure.mgmt.web import WebSiteManagementClient
from scanner.utils import (
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET,
    AZURE_TENANT_ID,
    AZURE_SUBSCRIPTION_ID,
    creds_ok,
)


def check_unrestricted_function_apps():
    """
    Returns findings for Function Apps that allow anonymous access or lack authentication.
    """
    if not creds_ok():
        raise Exception("Azure creds missing in .env")
    cred = ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
    )
    client = WebSiteManagementClient(cred, AZURE_SUBSCRIPTION_ID)
    findings = []
    for app in client.web_apps.list():
        # Only check Function Apps
        if app.kind and "functionapp" in app.kind:
            auth_settings = client.web_apps.get_auth_settings(
                app.resource_group, app.name
            )
            # If authentication is not enabled or allows anonymous access
            if not getattr(auth_settings, "enabled", False):
                findings.append(
                    {
                        "rule_id": "AZ-FunctionApp-Anonymous-001",
                        "service": "FunctionApp",
                        "resource_id": app.id,
                        "resource_name": app.name,
                        "resource_group": app.resource_group,
                        "title": "Function App allows anonymous access or lacks authentication",
                        "severity": "High",
                        "evidence": {
                            "auth_enabled": getattr(auth_settings, "enabled", None),
                            "default_provider": getattr(
                                auth_settings, "default_provider", None
                            ),
                        },
                        "remediation": [
                            "Enable authentication for the Function App.",
                            "Configure an identity provider (Azure AD, Facebook, Google, etc.)",
                        ],
                    }
                )
    return findings
