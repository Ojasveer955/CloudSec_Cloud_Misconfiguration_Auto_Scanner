# scanner/check_nsg.py
# Detect NSG rules that allow traffic from 0.0.0.0/0 (anywhere) on sensitive ports (22, 3389).

from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from scanner.utils import (
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET,
    AZURE_TENANT_ID,
    AZURE_SUBSCRIPTION_ID,
    creds_ok,
)


def _cred():
    if not creds_ok():
        raise Exception("Azure creds missing in .env")
    return ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
    )


def check_open_nsg_rules():
    cred = _cred()
    client = NetworkManagementClient(cred, AZURE_SUBSCRIPTION_ID)
    findings = []

    for nsg in client.network_security_groups.list_all():
        for rule in nsg.security_rules or []:
            src = rule.source_address_prefix
            if src in ["*", "0.0.0.0/0", "Internet"]:
                port = rule.destination_port_range
                if port in ["22", "3389", "*"]:  # SSH, RDP, or all ports
                    evidence = {
                        "nsg_name": nsg.name,
                        "rule_name": rule.name,
                        "source_address_prefix": src,
                        "destination_port_range": port,
                        "resource_id": nsg.id,
                    }
                    findings.append(
                        {
                            "rule_id": "AZ-NSG-OPEN-001",
                            "service": "NetworkSecurityGroup",
                            "resource_id": nsg.id,
                            "nsg_name": nsg.name,
                            "rule_name": rule.name,
                            "title": f"NSG allows {src} to port {port}",
                            "severity": "High",
                            "evidence": evidence,
                            "remediation": [
                                f"Restrict NSG rule {rule.name} on {nsg.name} to only trusted IP ranges.",
                                "Use Just-In-Time access or Azure Bastion for admin access.",
                            ],
                        }
                    )
    return findings
