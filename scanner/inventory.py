# scanner/inventory.py
# Connects to Azure using the service principal and lists storage accounts.
from azure.identity import ClientSecretCredential
from azure.mgmt.storage import StorageManagementClient
from scanner.utils import (
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET,
    AZURE_TENANT_ID,
    AZURE_SUBSCRIPTION_ID,
    creds_ok,
)


def get_credential():
    if not creds_ok():
        raise Exception(
            "Azure creds not found in .env. Fill AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID"
        )
    cred = ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
    )
    return cred


def list_storage_accounts():
    """
    Returns a list of storage accounts. Each item is a dict:
    {
      "name": "...",
      "id": "...",
      "resource_group": "...",
      "properties": <StorageAccount properties object>
    }
    """
    cred = get_credential()
    client = StorageManagementClient(cred, AZURE_SUBSCRIPTION_ID)

    accounts = []
    for sa in client.storage_accounts.list():
        # sa.id example:
        # /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<name>
        try:
            parts = sa.id.split("/")
            rg = parts[4]  # resource group name
        except Exception:
            rg = None

        # get_properties gives us the 'properties' object where allow_blob_public_access may live
        try:
            props = client.storage_accounts.get_properties(rg, sa.name)
        except Exception:
            props = None

        accounts.append(
            {"name": sa.name, "id": sa.id, "resource_group": rg, "properties": props}
        )

    return accounts
