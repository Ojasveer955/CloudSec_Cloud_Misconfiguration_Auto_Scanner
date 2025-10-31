# scanner/checks_aws_s3.py
# Security checks for AWS S3 buckets - detect public access misconfigurations.

import json
from scanner.utils_aws import get_aws_client


def check_s3_public_access(buckets):
    """
    Check S3 buckets for public access configurations.

    Detects three types of public access:
    1. Block Public Access settings disabled
    2. Public ACL grants (AllUsers or AuthenticatedUsers)
    3. Bucket policies allowing public access

    Args:
        buckets (list): List from list_s3_buckets()

    Returns:
        list: List of finding dictionaries containing security violations
    """
    s3_client = get_aws_client("s3")
    findings = []

    for bucket in buckets:
        bucket_name = bucket["name"]
        is_public = False
        evidence = {
            "bucket_name": bucket_name,
            "arn": bucket["arn"],
            "region": bucket["region"],
        }

        # Check 1: Block Public Access settings
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            pab_config = public_access_block.get("PublicAccessBlockConfiguration", {})

            # If any of these are False, bucket could be public
            block_public_acls = pab_config.get("BlockPublicAcls", False)
            ignore_public_acls = pab_config.get("IgnorePublicAcls", False)
            block_public_policy = pab_config.get("BlockPublicPolicy", False)
            restrict_public_buckets = pab_config.get("RestrictPublicBuckets", False)

            if not all(
                [
                    block_public_acls,
                    ignore_public_acls,
                    block_public_policy,
                    restrict_public_buckets,
                ]
            ):
                is_public = True
                evidence["public_access_block"] = {
                    "BlockPublicAcls": block_public_acls,
                    "IgnorePublicAcls": ignore_public_acls,
                    "BlockPublicPolicy": block_public_policy,
                    "RestrictPublicBuckets": restrict_public_buckets,
                }
                evidence["public_access_block_status"] = "Partially disabled"

        except Exception as e:
            # Check if it's NoSuchPublicAccessBlockConfiguration or other error
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if (
                error_code == "NoSuchPublicAccessBlockConfiguration"
                or "NoSuchPublicAccessBlockConfiguration" in str(type(e))
            ):
                # No block configuration = potentially public
                is_public = True
                evidence["public_access_block"] = "Not configured"
                evidence["public_access_block_status"] = "Not configured (vulnerable)"
            else:
                # Access denied or other error - note it but don't fail
                evidence["public_access_block_error"] = str(
                    e
                )  # Check 2: Bucket ACL - look for public grants
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_grants = []

            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("Type") == "Group":
                    uri = grantee.get("URI", "")
                    # Check for AllUsers or AuthenticatedUsers
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        is_public = True
                        public_grants.append(
                            {
                                "grantee": uri.split("/")[
                                    -1
                                ],  # Get just the group name
                                "permission": grant.get("Permission"),
                            }
                        )

            if public_grants:
                evidence["public_acl_grants"] = public_grants

        except Exception as e:
            evidence["acl_check_error"] = str(e)

        # Check 3: Bucket Policy - check for wildcard principals
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy_response["Policy"])

            public_statements = []
            for statement in policy_doc.get("Statement", []):
                principal = statement.get("Principal", {})
                effect = statement.get("Effect", "")

                # Check if principal is wildcard and effect is Allow
                is_wildcard_principal = (
                    principal == "*"
                    or principal.get("AWS") == "*"
                    or (
                        isinstance(principal.get("AWS"), list)
                        and "*" in principal.get("AWS", [])
                    )
                )

                if is_wildcard_principal and effect == "Allow":
                    is_public = True
                    public_statements.append(
                        {
                            "effect": effect,
                            "principal": principal,
                            "action": statement.get("Action"),
                            "resource": statement.get("Resource"),
                        }
                    )

            if public_statements:
                evidence["public_policy_statements"] = public_statements

        except Exception as e:
            # Check if it's NoSuchBucketPolicy or another error
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if error_code != "NoSuchBucketPolicy" and "NoSuchBucketPolicy" not in str(
                type(e)
            ):
                # Not a "no policy" error, so record it
                evidence["policy_check_error"] = str(e)

        # Create finding if bucket has any public access
        if is_public:
            # Determine severity based on what's exposed
            severity = "High"
            if (
                "public_acl_grants" in evidence
                or "public_policy_statements" in evidence
            ):
                severity = "Critical"  # Active public access

            findings.append(
                {
                    "rule_id": "AWS-S3-Public-001",
                    "service": "S3",
                    "resource_id": bucket["arn"],
                    "resource_name": bucket_name,
                    "title": f"S3 bucket '{bucket_name}' may be publicly accessible",
                    "severity": severity,
                    "evidence": evidence,
                    "remediation": [
                        "Enable S3 Block Public Access for the bucket",
                        "Review and remove public ACL grants (AllUsers, AuthenticatedUsers)",
                        "Review bucket policy for wildcard (*) principals",
                        "AWS CLI command: aws s3api put-public-access-block --bucket "
                        + bucket_name
                        + " --public-access-block-configuration "
                        + "'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                        "Ensure data is not exposed to the public internet",
                    ],
                }
            )

    return findings
