# scanner/checks_azure.py
# Small rule to detect storage accounts that allow public blob access.


def check_storage_public_blob_access(storage_accounts):
    """
    Input: list from list_storage_accounts()
    Output: list of findings (dicts)
    """
    findings = []
    for sa in storage_accounts:
        props = sa.get("properties")
        allow_public = None

        # props may be a model object with attributes, try attribute access
        try:
            allow_public = getattr(props, "allow_blob_public_access", None)
        except Exception:
            allow_public = None

        # sometimes it's inside 'properties' as a dict-like, try as mapping
        if allow_public is None:
            try:
                # props may be a 'dict' or object with item access
                allow_public = (
                    props.get("allow_blob_public_access")
                    if hasattr(props, "get")
                    else None
                )
            except Exception:
                allow_public = None

        # We consider True (explicit) a finding
        if allow_public is True:
            evidence = {
                "allow_blob_public_access": True,
                "storage_account": sa.get("name"),
                "resource_group": sa.get("resource_group"),
                "id": sa.get("id"),
            }
            findings.append(
                {
                    "rule_id": "AZ-Storage-PublicBlob-001",
                    "service": "StorageAccount",
                    "resource_id": sa.get("id"),
                    "resource_name": sa.get("name"),
                    "resource_group": sa.get("resource_group"),
                    "title": "Storage account allows public blob access",
                    "severity": "High",
                    "evidence": evidence,
                    "remediation": [
                        "Set allow_blob_public_access on the storage account to false.",
                        "Audit containers and set container public access to 'private'.",
                    ],
                }
            )
    return findings
