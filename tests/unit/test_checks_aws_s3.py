# tests/unit/test_checks_aws_s3.py
# Unit tests for AWS S3 security checks

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from scanner.checks_aws_s3 import check_s3_public_access


class TestS3PublicAccessChecks:
    """Test cases for AWS S3 public access security checks."""

    @patch("scanner.checks_aws_s3.get_aws_client")
    def test_public_bucket_no_block_public_access(self, mock_get_client):
        """Test detection of buckets without Block Public Access configured."""
        # Arrange
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        # Simulate no public access block configuration
        no_config_error = Exception("NoSuchPublicAccessBlockConfiguration")
        no_config_error.response = {
            "Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}
        }
        mock_s3.get_public_access_block.side_effect = no_config_error
        mock_s3.get_bucket_acl.return_value = {"Grants": []}

        no_policy_error = Exception("NoSuchBucketPolicy")
        no_policy_error.response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3.get_bucket_policy.side_effect = no_policy_error

        buckets = [
            {
                "name": "test-public-bucket",
                "creation_date": datetime(2024, 1, 1),
                "region": "us-east-1",
                "arn": "arn:aws:s3:::test-public-bucket",
            }
        ]

        # Act
        findings = check_s3_public_access(buckets)

        # Assert
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AWS-S3-Public-001"
        assert findings[0]["severity"] in ["High", "Critical"]
        assert findings[0]["resource_name"] == "test-public-bucket"
        assert "publicly accessible" in findings[0]["title"].lower()
        assert "Not configured" in findings[0]["evidence"]["public_access_block"]

    @patch("scanner.checks_aws_s3.get_aws_client")
    def test_public_bucket_with_public_acl(self, mock_get_client):
        """Test detection of buckets with public ACL grants."""
        # Arrange
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        # Simulate public ACL grant
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ]
        }

        no_policy_error = Exception("NoSuchBucketPolicy")
        no_policy_error.response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3.get_bucket_policy.side_effect = no_policy_error

        buckets = [
            {
                "name": "public-acl-bucket",
                "creation_date": datetime(2024, 1, 1),
                "region": "us-west-2",
                "arn": "arn:aws:s3:::public-acl-bucket",
            }
        ]

        # Act
        findings = check_s3_public_access(buckets)

        # Assert
        assert len(findings) == 1
        assert findings[0]["severity"] == "Critical"  # Active public access
        assert "public_acl_grants" in findings[0]["evidence"]
        assert findings[0]["evidence"]["public_acl_grants"][0]["grantee"] == "AllUsers"
        assert findings[0]["evidence"]["public_acl_grants"][0]["permission"] == "READ"

    @patch("scanner.checks_aws_s3.get_aws_client")
    def test_public_bucket_with_wildcard_policy(self, mock_get_client):
        """Test detection of buckets with public bucket policies."""
        # Arrange
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        # Simulate bucket policy with wildcard principal
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_policy.return_value = {
            "Policy": """{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::public-policy-bucket/*"
                    }
                ]
            }"""
        }

        buckets = [
            {
                "name": "public-policy-bucket",
                "creation_date": datetime(2024, 1, 1),
                "region": "eu-west-1",
                "arn": "arn:aws:s3:::public-policy-bucket",
            }
        ]

        # Act
        findings = check_s3_public_access(buckets)

        # Assert
        assert len(findings) == 1
        assert findings[0]["severity"] == "Critical"
        assert "public_policy_statements" in findings[0]["evidence"]
        assert (
            findings[0]["evidence"]["public_policy_statements"][0]["principal"] == "*"
        )
        assert (
            findings[0]["evidence"]["public_policy_statements"][0]["effect"] == "Allow"
        )

    @patch("scanner.checks_aws_s3.get_aws_client")
    def test_secure_bucket_no_findings(self, mock_get_client):
        """Test that secure buckets produce no findings."""
        # Arrange
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        # Simulate fully secured bucket
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "account-owner-id"},
                    "Permission": "FULL_CONTROL",
                }
            ]
        }

        no_policy_error = Exception("NoSuchBucketPolicy")
        no_policy_error.response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3.get_bucket_policy.side_effect = no_policy_error

        buckets = [
            {
                "name": "secure-bucket",
                "creation_date": datetime(2024, 1, 1),
                "region": "us-east-1",
                "arn": "arn:aws:s3:::secure-bucket",
            }
        ]

        # Act
        findings = check_s3_public_access(buckets)

        # Assert
        assert len(findings) == 0

    @patch("scanner.checks_aws_s3.get_aws_client")
    def test_multiple_buckets_mixed_security(self, mock_get_client):
        """Test scanning multiple buckets with different security postures."""
        # Arrange
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        call_count = [0]

        def get_public_access_block_side_effect(Bucket):
            call_count[0] += 1
            if call_count[0] == 1:  # First bucket - no config
                no_config_error = Exception("NoSuchPublicAccessBlockConfiguration")
                no_config_error.response = {
                    "Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}
                }
                raise no_config_error
            else:  # Second bucket - fully secured
                return {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                }

        mock_s3.get_public_access_block.side_effect = (
            get_public_access_block_side_effect
        )
        mock_s3.get_bucket_acl.return_value = {"Grants": []}

        no_policy_error = Exception("NoSuchBucketPolicy")
        no_policy_error.response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        mock_s3.get_bucket_policy.side_effect = no_policy_error

        buckets = [
            {
                "name": "insecure-bucket",
                "creation_date": datetime(2024, 1, 1),
                "region": "us-east-1",
                "arn": "arn:aws:s3:::insecure-bucket",
            },
            {
                "name": "secure-bucket",
                "creation_date": datetime(2024, 1, 1),
                "region": "us-east-1",
                "arn": "arn:aws:s3:::secure-bucket",
            },
        ]

        # Act
        findings = check_s3_public_access(buckets)

        # Assert
        assert len(findings) == 1
        assert findings[0]["resource_name"] == "insecure-bucket"

    @patch("scanner.checks_aws_s3.get_aws_client")
    def test_empty_bucket_list(self, mock_get_client):
        """Test handling of empty bucket list."""
        # Arrange
        mock_s3 = MagicMock()
        mock_get_client.return_value = mock_s3

        buckets = []

        # Act
        findings = check_s3_public_access(buckets)

        # Assert
        assert len(findings) == 0
        assert findings == []
