# scanner/inventory_aws.py
# AWS resource inventory - lists S3 buckets and their metadata.

from scanner.utils_aws import get_aws_client, aws_creds_ok


def list_s3_buckets():
    """
    List all S3 buckets in the AWS account.

    Returns a list of S3 bucket dictionaries. Each item contains:
    {
      "name": "bucket-name",
      "creation_date": datetime,
      "region": "us-east-1",
      "arn": "arn:aws:s3:::bucket-name"
    }

    Returns:
        list: List of bucket dictionaries

    Raises:
        Exception: If AWS credentials are not configured
    """
    if not aws_creds_ok():
        raise Exception(
            "AWS credentials not found in .env. "
            "Fill AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION"
        )

    s3_client = get_aws_client("s3")

    buckets = []

    try:
        # List all buckets
        response = s3_client.list_buckets()

        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            creation_date = bucket["CreationDate"]

            # Get bucket region
            region = "us-east-1"  # Default
            try:
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                # LocationConstraint is None for us-east-1, otherwise it's the region name
                location_constraint = location_response.get("LocationConstraint")
                if location_constraint:
                    region = location_constraint
            except Exception as e:
                # If we can't get location, use default and continue
                print(f"Warning: Could not get location for bucket {bucket_name}: {e}")

            buckets.append(
                {
                    "name": bucket_name,
                    "creation_date": creation_date,
                    "region": region,
                    "arn": f"arn:aws:s3:::{bucket_name}",
                }
            )

    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
        raise

    return buckets
