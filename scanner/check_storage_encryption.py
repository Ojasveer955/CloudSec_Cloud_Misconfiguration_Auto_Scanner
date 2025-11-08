# scanner/check_storage_encryption.py
# Checks if storage accounts have encryption enabled (Azure-managed or customer-managed keys).


def check_storage_encryption(storage_accounts):
    """
    Checks if storage accounts have encryption enabled (Azure-managed or customer-managed keys).
    Returns a list of findings (dicts).
    """
    findings = []
    for sa in storage_accounts:
        props = sa.get("properties")
        encryption = None
        try:
            encryption = getattr(props, "encryption", None)
        except Exception:
            encryption = None
        if encryption is None and hasattr(props, "get"):
            encryption = props.get("encryption")

        # If encryption is missing or not enabled, flag it
        if not encryption or not getattr(encryption, "services", None):
            evidence = {}
            if encryption:
                # Try to extract key details
                key_source = getattr(encryption, "key_source", None)
                key_vault_properties = getattr(encryption, "key_vault_properties", None)
                evidence["key_source"] = str(key_source)
                if key_vault_properties:
                    evidence["key_vault_properties"] = str(key_vault_properties)
            findings.append(
                {
                    "rule_id": "AZ-Storage-Encryption-001",
                    "service": "StorageAccount",
                    "resource_id": sa.get("id"),
                    "resource_name": sa.get("name"),
                    "resource_group": sa.get("resource_group"),
                    "title": "Storage account does not have encryption enabled",
                    "severity": "High",
                    "evidence": evidence,
                    "remediation": [
                        "Enable encryption for the storage account using Azure-managed or customer-managed keys."
                    ],
                }
            )
        else:
            # Check if encryption is enabled for blobs
            blob_encryption = getattr(encryption.services, "blob", None)
            if blob_encryption and not getattr(blob_encryption, "enabled", True):
                evidence = {
                    "enabled": getattr(blob_encryption, "enabled", None),
                    "last_enabled_time": str(
                        getattr(blob_encryption, "last_enabled_time", None)
                    ),
                }
                findings.append(
                    {
                        "rule_id": "AZ-Storage-Encryption-001",
                        "service": "StorageAccount",
                        "resource_id": sa.get("id"),
                        "resource_name": sa.get("name"),
                        "resource_group": sa.get("resource_group"),
                        "title": "Storage account blob encryption is not enabled",
                        "severity": "High",
                        "evidence": evidence,
                        "remediation": [
                            "Enable blob encryption for the storage account."
                        ],
                    }
                )
    return findings
