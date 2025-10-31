# scanner/utils_aws.py
# AWS credential management and session utilities.

import os
import boto3
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# AWS Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv(
    "AWS_REGION", "us-east-1"
)  # Default to us-east-1 if not specified


def aws_creds_ok():
    """
    Check if AWS credentials are properly configured.

    Returns:
        bool: True if all required AWS credentials are set, False otherwise
    """
    return all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY])


def get_aws_session():
    """
    Create and return an authenticated boto3 Session.

    Returns:
        boto3.Session: Authenticated AWS session

    Raises:
        Exception: If AWS credentials are not configured
    """
    if not aws_creds_ok():
        raise Exception(
            "AWS credentials not found in .env. "
            "Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and optionally AWS_REGION"
        )

    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )

    return session


def get_aws_client(service_name, region=None):
    """
    Get an AWS service client for the specified service.

    Args:
        service_name (str): AWS service name (e.g., 's3', 'ec2', 'iam')
        region (str, optional): AWS region. Defaults to AWS_REGION from env

    Returns:
        boto3.client: AWS service client

    Raises:
        Exception: If AWS credentials are not configured
    """
    session = get_aws_session()
    client_region = region or AWS_REGION
    return session.client(service_name, region_name=client_region)
