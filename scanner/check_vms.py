# scanner/check_vms.py
# Lists VMs and flags any VM that has a public IP attached.

from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from scanner.utils import (
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET,
    AZURE_TENANT_ID,
    AZURE_SUBSCRIPTION_ID,
    creds_ok,
)


def _credential():
    if not creds_ok():
        raise Exception("Azure creds missing in .env")
    return ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
    )


def list_vms_with_public_ip():
    cred = _credential()
    compute = ComputeManagementClient(cred, AZURE_SUBSCRIPTION_ID)
    network = NetworkManagementClient(cred, AZURE_SUBSCRIPTION_ID)

    findings = []
    for vm in compute.virtual_machines.list_all():
        vm_name = vm.name
        nic_refs = [n.id for n in vm.network_profile.network_interfaces]
        vm_public_ips = []

        for nic_id in nic_refs:
            parts = nic_id.split("/")
            rg = parts[4]
            nic_name = parts[-1]
            nic = network.network_interfaces.get(rg, nic_name)

            for ipconf in nic.ip_configurations:
                pip_ref = getattr(ipconf, "public_ip_address", None)
                if pip_ref:
                    pip_parts = pip_ref.id.split("/")
                    pip_rg = pip_parts[4]
                    pip_name = pip_parts[-1]
                    pip = network.public_ip_addresses.get(pip_rg, pip_name)
                    ip_address = getattr(pip, "ip_address", None)
                    vm_public_ips.append({"nic": nic_name, "public_ip": ip_address})

        if vm_public_ips:
            evidence = {
                "vm_name": vm_name,
                "resource_id": vm.id,
                "public_ips": vm_public_ips,
            }
            findings.append(
                {
                    "rule_id": "AZ-VM-PUBIP-001",
                    "service": "VirtualMachine",
                    "vm_name": vm_name,
                    "resource_id": vm.id,
                    "public_ips": vm_public_ips,
                    "title": "VM has public IP(s)",
                    "severity": "Medium",
                    "evidence": evidence,
                    "remediation": [
                        "Remove public IP from NIC if not required",
                        "Use Azure Bastion or VPN instead of public IP",
                    ],
                }
            )
    return findings
