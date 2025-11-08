# scanner/utils.py
# Simple helper: loads environment variables from the .env file.
from dotenv import load_dotenv
import os

# load .env in project root
load_dotenv()

AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
DB_PATH = os.getenv("DB_PATH", "./scanner_azure.db")


def creds_ok():
    return all(
        [AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID]
    )
