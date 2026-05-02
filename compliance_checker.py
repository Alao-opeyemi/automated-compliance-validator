import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import NoCredentialsError, PartialCredentialsError


def check_s3_compliance():
    s3 = boto3.client("s3")
    findings = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]

        # NIST 800-53 AC-3 / PCI-DSS 1.3 - Block public access
        try:
            block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            required = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
            if not all(block.get(key, False) for key in required):
                findings.append(
                    {
                        "resource": name,
                        "violation": "Public access block is incomplete",
                        "severity": "HIGH",
                        "standards": ["NIST 800-53 AC-3", "PCI-DSS 1.3", "SOC 2 CC6.1"],
                    }
                )
        except Exception:
            findings.append(
                {
                    "resource": name,
                    "violation": "Public access block is not configured",
                    "severity": "CRITICAL",
                    "standards": ["NIST 800-53 AC-3", "PCI-DSS 1.3"],
                }
            )

        # NIST 800-53 SC-28 / ISO 27001 A.10.1 - Encryption at rest
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            findings.append(
                {
                    "resource": name,
                    "violation": "Server-side encryption is not enabled",
                    "severity": "HIGH",
                    "standards": ["NIST 800-53 SC-28", "ISO 27001 A.10.1", "PCI-DSS 3.5"],
                }
            )

        # NIST 800-53 AU-2 / SOC 2 CC7.2 - Access logging
        try:
            logging_config = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_config:
                findings.append(
                    {
                        "resource": name,
                        "violation": "Access logging is not enabled",
                        "severity": "MEDIUM",
                        "standards": ["NIST 800-53 AU-2", "SOC 2 CC7.2", "ISO 27001 A.12.4"],
                    }
                )
        except Exception:
            pass

    return findings


def write_report(findings, warnings=None, scan_status="COMPLETED"):
    warnings = warnings or []

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_status": scan_status,
        "standards_checked": ["NIST 800-53 Rev 5", "ISO 27001", "SOC 2", "PCI-DSS"],
        "total_findings": len(findings),
        "critical": len([finding for finding in findings if finding["severity"] == "CRITICAL"]),
        "high": len([finding for finding in findings if finding["severity"] == "HIGH"]),
        "medium": len([finding for finding in findings if finding["severity"] == "MEDIUM"]),
        "warnings": warnings,
        "findings": findings,
    }

    with open("compliance_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        write_report(check_s3_compliance())
    except (NoCredentialsError, PartialCredentialsError):
        write_report(
            [],
            warnings=["AWS credentials were not provided. The live S3 compliance scan was skipped."],
            scan_status="SKIPPED",
        )
