# run_scan.py
from scanner.inventory import list_storage_accounts
from scanner.checks_azure import check_storage_public_blob_access
from scanner.check_storage_encryption import check_storage_encryption
from scanner.check_vms import list_vms_with_public_ip
from scanner.check_nsg import check_open_nsg_rules
from scanner.check_function_apps import check_unrestricted_function_apps
import json


def run():
    findings = []

    print("Scanning storage accounts...")
    accounts = list_storage_accounts()
    findings += check_storage_public_blob_access(accounts)
    print("Checking storage account encryption...")
    findings += check_storage_encryption(accounts)

    print("Scanning virtual machines for public IPs...")
    findings += list_vms_with_public_ip()

    print("Scanning NSGs for open rules...")
    findings += check_open_nsg_rules()

    print("Scanning Function Apps for anonymous access...")
    findings += check_unrestricted_function_apps()

    print(f"\nTotal findings: {len(findings)}")
    if findings:
        for f in findings:
            print("\n------------------------------")
            print(f"Rule ID: {f.get('rule_id')}")
            print(f"Service: {f.get('service')}")
            print(f"Title: {f.get('title')}")
            print(f"Severity: {f.get('severity')}")
            print(f"Resource: {f.get('resource_name', f.get('resource_id'))}")
            print("Evidence:")
            print(json.dumps(f.get("evidence"), indent=2, ensure_ascii=False))
            print("Remediation:")
            if isinstance(f.get("remediation"), list):
                for r in f.get("remediation"):
                    print(f"- {r}")
            else:
                print(f.get("remediation"))
        print("\n------------------------------")
    else:
        print("No findings detected.")


if __name__ == "__main__":
    run()
