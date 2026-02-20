"""AWS session management and helper utilities."""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from src.utils.exceptions import AWSAuthenticationError
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AWSSessionManager:
    """Manages boto3 sessions, credential resolution, and cross-account role assumption."""

    def __init__(self, profile_name: str = None, region: str = "us-east-1"):
        self.profile_name = profile_name
        self.region = region
        self.session = None

    def create_session(self) -> boto3.Session:
        """Create a boto3 session using profile or default credential chain."""
        try:
            if self.profile_name:
                self.session = boto3.Session(
                    profile_name=self.profile_name,
                    region_name=self.region,
                )
            else:
                self.session = boto3.Session(region_name=self.region)

            # Validate credentials are actually resolvable
            self.session.client("sts").get_caller_identity()
            logger.debug("AWS session created successfully.")
            return self.session

        except ProfileNotFound:
            raise AWSAuthenticationError(
                f"AWS profile '{self.profile_name}' not found in ~/.aws/credentials"
            )
        except NoCredentialsError:
            raise AWSAuthenticationError(
                "No AWS credentials found. Configure via environment variables, "
                "~/.aws/credentials, or an IAM role."
            )
        except ClientError as e:
            raise AWSAuthenticationError(f"AWS authentication failed: {e}")

    def assume_role(self, role_arn: str, session_name: str = "SecurityScanner") -> boto3.Session:
        """Assume an IAM role for cross-account scanning."""
        if not self.session:
            self.create_session()

        try:
            sts = self.session.client("sts")
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            creds = response["Credentials"]

            assumed_session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
            logger.info(f"Successfully assumed role: {role_arn}")
            return assumed_session

        except ClientError as e:
            raise AWSAuthenticationError(f"Failed to assume role {role_arn}: {e}")

    def get_account_id(self) -> str:
        """Return the AWS account ID for the active session."""
        if not self.session:
            self.create_session()
        return self.session.client("sts").get_caller_identity()["Account"]

    def get_enabled_regions(self) -> list:
        """Return all enabled regions for the current account."""
        if not self.session:
            self.create_session()
        ec2 = self.session.client("ec2", region_name="us-east-1")
        regions = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        return [r["RegionName"] for r in regions["Regions"]]
