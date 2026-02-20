"""Configuration management — loads from CLI args or YAML config file."""
import yaml
from dataclasses import dataclass, field
from typing import List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

ALL_SERVICES = ["s3", "iam", "ec2", "rds", "vpc", "cloudtrail"]


@dataclass
class ScannerConfig:
    profile: Optional[str] = None
    region: str = "us-east-1"
    services: List[str] = field(default_factory=lambda: list(ALL_SERVICES))
    output_path: str = "report.html"
    output_format: str = "html"
    role_arn: Optional[str] = None
    min_severity: str = "LOW"

    @classmethod
    def from_dict(cls, d: dict) -> "ScannerConfig":
        services_raw = d.get("services", ALL_SERVICES)
        if services_raw == "all":
            services = ALL_SERVICES
        elif isinstance(services_raw, str):
            services = [s.strip() for s in services_raw.split(",")]
        else:
            services = list(services_raw)

        return cls(
            profile=d.get("profile"),
            region=d.get("region", "us-east-1"),
            services=services,
            output_path=d.get("output", "report.html"),
            output_format=d.get("format", "html"),
            role_arn=d.get("role_arn"),
            min_severity=d.get("min_severity", "LOW"),
        )

    @classmethod
    def from_yaml(cls, path: str, profile_name: str = "default") -> "ScannerConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        profile_data = data.get(profile_name, data.get("default", {}))
        logger.info(f"Loaded config profile '{profile_name}' from {path}")
        return cls.from_dict(profile_data)
