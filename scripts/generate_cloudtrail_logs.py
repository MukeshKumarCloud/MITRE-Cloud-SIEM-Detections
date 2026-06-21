"""
generate_cloudtrail_logs.py
----------------------------
Generates simulated AWS CloudTrail log events for 5 MITRE ATT&CK cloud TTPs.
Output: sample_cloudtrail_logs.json (one JSON object per line — NDJSON format)

MITRE TTPs covered:
  T1078 - Valid Accounts (credential abuse / impossible travel)
  T1530 - Data from Cloud Storage (mass S3 GetObject)
  T1537 - Transfer Data to Cloud Account (cross-account S3 copy)
  T1580 - Cloud Infrastructure Discovery (API enumeration)
  T1136 - Create Account (new IAM user creation)

Usage:
  python3 generate_cloudtrail_logs.py
  Output file: ../sample-logs/sample_cloudtrail_logs.json
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
import os

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────

OUTPUT_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "sample-logs", "sample_cloudtrail_logs.json"
)

# How many events to generate per TTP
EVENTS_PER_TTP = {
    "T1078": 15,   # credential abuse - needs enough to show pattern
    "T1530": 40,   # mass S3 reads - high volume is the detection signal
    "T1537": 10,   # cross-account copy - fewer but distinct
    "T1580": 25,   # enumeration - rapid-fire API calls
    "T1136": 5,    # account creation - rare, each one is suspicious
}

# Simulated legitimate infrastructure
LEGITIMATE_IPS = [
    "10.0.1.45", "10.0.2.110", "192.168.1.20",    # internal RFC1918
    "203.0.113.10",                                  # known corp egress (TEST-NET)
]

# Attacker IPs (geographically implausible relative to "corp" IPs above)
ATTACKER_IPS = [
    "185.220.101.47",  # Tor exit node range (example)
    "45.33.32.156",    # random external
    "91.108.4.200",    # Eastern Europe range (example)
    "103.21.244.0",    # APAC range (example)
]

AWS_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
ATTACKER_REGION = "eu-central-1"   # region corp never uses — detection signal

# Simulated IAM users and roles
LEGITIMATE_USERS = ["alice@corp.com", "bob@corp.com", "ci-deploy-role"]
ATTACKER_USER = "alice@corp.com"    # T1078: attacker uses a REAL stolen account
NEW_MALICIOUS_USER = "support-automation"   # T1136: attacker creates this

ACCOUNT_ID = "123456789012"
ATTACKER_ACCOUNT_ID = "998877665544"  # external account for T1537

S3_BUCKET = "corp-prod-data-lake"
SENSITIVE_S3_KEYS = [
    "finance/Q4-2024-revenue.csv",
    "hr/employee-salaries-2024.xlsx",
    "customers/full-export-2024-12.csv",
    "secrets/db-connection-strings.txt",
    "engineering/source-code-archive.tar.gz",
]

# ─────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────

def make_timestamp(base_time: datetime, offset_seconds: int = 0) -> str:
    """Return ISO 8601 UTC timestamp string."""
    t = base_time + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event_id() -> str:
    """Generate a realistic CloudTrail eventID (UUID4)."""
    return str(uuid.uuid4())


def base_event(event_name: str, source: str, region: str,
               user: str, source_ip: str, timestamp: str,
               request_params: dict, response_elements: dict,
               error_code: str = None, error_message: str = None,
               user_identity_type: str = "IAMUser") -> dict:
    """
    Build a CloudTrail-shaped event dict.
    This matches the real CloudTrail JSON schema fields used in SIEM detection rules.
    """
    event = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": user_identity_type,
            "principalId": f"AIDAEXAMPLE{random.randint(10000, 99999)}",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{user}",
            "accountId": ACCOUNT_ID,
            "userName": user,
            "accessKeyId": f"ASIA{random.randint(100000000000, 999999999999)}"
        },
        "eventTime": timestamp,
        "eventSource": source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": random.choice([
            "aws-cli/2.15.0 Python/3.12.0 Linux/6.7.4",
            "Boto3/1.34.0 Python/3.11.5",
            "console.amazonaws.com",
            "aws-sdk-java/1.12.600",
        ]),
        "requestParameters": request_params,
        "responseElements": response_elements,
        "eventID": make_event_id(),
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT_ID,
        "mitreAttackTechnique": "",   # custom field — we'll set per TTP
        "mitreAttackTactic": "",      # custom field — we'll set per TTP
    }

    # Add error fields only if present (real CloudTrail behavior)
    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = error_message or error_code

    return event


# ─────────────────────────────────────────────────────────────
# TTP EVENT GENERATORS
# ─────────────────────────────────────────────────────────────

def generate_T1078_events(base_time: datetime, count: int) -> list:
    """
    T1078 - Valid Accounts
    Tactic: Initial Access / Persistence / Privilege Escalation

    Attack pattern simulated:
    - Legitimate user logs in from known IP (normal)
    - Same user then authenticates from a foreign IP within minutes (impossible travel)
    - Followed by API calls from the attacker IP — same session, different geo

    Detection signal:
    - Same userName, two different sourceIPAddresses within short window
    - sourceIPAddress not in known legitimate IP range
    - ConsoleLogin from unusual region
    """
    events = []
    user = ATTACKER_USER

    # Event 1–5: Normal logins from legit IP (background noise)
    for i in range(5):
        t = make_timestamp(base_time, offset_seconds=i * 300)
        ev = base_event(
            event_name="ConsoleLogin",
            source="signin.amazonaws.com",
            region="us-east-1",
            user=user,
            source_ip=LEGITIMATE_IPS[0],
            timestamp=t,
            request_params={},
            response_elements={"ConsoleLogin": "Success"},
        )
        ev["mitreAttackTechnique"] = "T1078 - Valid Accounts"
        ev["mitreAttackTactic"] = "Initial Access"
        ev["additionalEventData"] = {
            "MobileVersion": "No",
            "LoginTo": "https://console.aws.amazon.com/console/home",
            "MFAUsed": "Yes"
        }
        events.append(ev)

    # Event 6: ATTACKER login — same user, foreign IP, 8 minutes after last legit login
    attacker_login_time = make_timestamp(base_time, offset_seconds=5 * 300 + 480)
    ev = base_event(
        event_name="ConsoleLogin",
        source="signin.amazonaws.com",
        region=ATTACKER_REGION,
        user=user,
        source_ip=ATTACKER_IPS[0],
        timestamp=attacker_login_time,
        request_params={},
        response_elements={"ConsoleLogin": "Success"},
    )
    ev["mitreAttackTechnique"] = "T1078 - Valid Accounts"
    ev["mitreAttackTactic"] = "Initial Access"
    ev["additionalEventData"] = {
        "MobileVersion": "No",
        "LoginTo": "https://console.aws.amazon.com/console/home",
        "MFAUsed": "No"    # DETECTION SIGNAL: MFA absent on attacker session
    }
    events.append(ev)

    # Events 7–15: Post-compromise API calls from attacker IP
    post_compromise_actions = [
        ("GetCallerIdentity", "sts.amazonaws.com", {}, {"Account": ACCOUNT_ID}),
        ("ListBuckets", "s3.amazonaws.com", {}, {"buckets": [S3_BUCKET]}),
        ("ListRoles", "iam.amazonaws.com", {}, {}),
        ("ListUsers", "iam.amazonaws.com", {}, {}),
        ("GetAccountAuthorizationDetails", "iam.amazonaws.com", {}, {}),
        ("DescribeInstances", "ec2.amazonaws.com", {}, {}),
        ("ListSecrets", "secretsmanager.amazonaws.com", {}, {}),
        ("GetSecretValue", "secretsmanager.amazonaws.com",
            {"secretId": "prod/db/password"}, {"SecretString": "REDACTED"}),
        ("ListKeys", "kms.amazonaws.com", {}, {}),
    ]
    for i, (action, svc, req, resp) in enumerate(post_compromise_actions):
        t = make_timestamp(base_time, offset_seconds=5 * 300 + 480 + (i + 1) * 60)
        ev = base_event(
            event_name=action,
            source=svc,
            region=ATTACKER_REGION,
            user=user,
            source_ip=ATTACKER_IPS[0],
            timestamp=t,
            request_params=req,
            response_elements=resp,
        )
        ev["mitreAttackTechnique"] = "T1078 - Valid Accounts"
        ev["mitreAttackTactic"] = "Credential Access"
        events.append(ev)

    return events


def generate_T1530_events(base_time: datetime, count: int) -> list:
    """
    T1530 - Data from Cloud Storage Object
    Tactic: Collection

    Attack pattern simulated:
    - Rapid, sequential GetObject calls to sensitive S3 keys
    - All from same IP in short window (automated exfiltration tool behavior)
    - Unusually high RequestCount for a single user in <10 minutes

    Detection signal:
    - High volume GetObject from single sourceIPAddress in short window
    - Access to key paths matching sensitive patterns (finance/, hr/, secrets/)
    - User has not accessed this bucket before (first-seen-bucket access)
    """
    events = []
    user = ATTACKER_USER

    # Simulate attacker bulk-reading the bucket
    for i in range(count):
        # Cycle through sensitive keys, repeating (simulates iterating all objects)
        s3_key = SENSITIVE_S3_KEYS[i % len(SENSITIVE_S3_KEYS)]
        t = make_timestamp(base_time, offset_seconds=3600 + i * 15)  # 1hr offset, 15s apart

        ev = base_event(
            event_name="GetObject",
            source="s3.amazonaws.com",
            region="us-east-1",
            user=user,
            source_ip=ATTACKER_IPS[1],
            timestamp=t,
            request_params={
                "bucketName": S3_BUCKET,
                "key": s3_key
            },
            response_elements=None,
        )
        ev["mitreAttackTechnique"] = "T1530 - Data from Cloud Storage"
        ev["mitreAttackTactic"] = "Collection"
        ev["resources"] = [
            {
                "type": "AWS::S3::Object",
                "ARN": f"arn:aws:s3:::{S3_BUCKET}/{s3_key}"
            }
        ]
        events.append(ev)

    return events


def generate_T1537_events(base_time: datetime, count: int) -> list:
    """
    T1537 - Transfer Data to Cloud Account
    Tactic: Exfiltration

    Attack pattern simulated:
    - CopyObject calls from corp bucket to attacker-controlled external account
    - The destination bucket is in a different AWS account (ATTACKER_ACCOUNT_ID)
    - PutBucketPolicy to add cross-account access, then CopyObject in bulk

    Detection signal:
    - CopyObject where x-amz-copy-source and destination bucket differ in account ownership
    - PutBucketPolicy granting access to unknown external account ID
    - Events from an IP not seen in normal operations
    """
    events = []
    user = ATTACKER_USER

    # Event 1: Attacker first adds a bucket policy granting cross-account access
    t = make_timestamp(base_time, offset_seconds=7200)
    ev = base_event(
        event_name="PutBucketPolicy",
        source="s3.amazonaws.com",
        region="us-east-1",
        user=user,
        source_ip=ATTACKER_IPS[2],
        timestamp=t,
        request_params={
            "bucketName": S3_BUCKET,
            "policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT_ID}:root"},
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{S3_BUCKET}",
                        f"arn:aws:s3:::{S3_BUCKET}/*"
                    ]
                }]
            })
        },
        response_elements=None,
    )
    ev["mitreAttackTechnique"] = "T1537 - Transfer Data to Cloud Account"
    ev["mitreAttackTactic"] = "Exfiltration"
    events.append(ev)

    # Events 2–10: CopyObject calls — exfiltrating to attacker bucket
    attacker_bucket = "attacker-exfil-bucket-xk92m"
    for i in range(count - 1):
        s3_key = SENSITIVE_S3_KEYS[i % len(SENSITIVE_S3_KEYS)]
        t = make_timestamp(base_time, offset_seconds=7200 + 120 + i * 30)

        ev = base_event(
            event_name="CopyObject",
            source="s3.amazonaws.com",
            region="us-east-1",
            user=user,
            source_ip=ATTACKER_IPS[2],
            timestamp=t,
            request_params={
                "destinationBucket": attacker_bucket,
                "destinationKey": s3_key,
                "x-amz-copy-source": f"{S3_BUCKET}/{s3_key}",
                "x-amz-copy-source-account": ACCOUNT_ID,
            },
            response_elements={
                "CopyObjectResult": {
                    "eTag": f"\"d41d8cd98f00b204e980099{i:05d}\"",
                    "lastModified": make_timestamp(base_time, offset_seconds=7200 + 120 + i * 30)
                }
            },
        )
        ev["mitreAttackTechnique"] = "T1537 - Transfer Data to Cloud Account"
        ev["mitreAttackTactic"] = "Exfiltration"
        ev["externalAccountId"] = ATTACKER_ACCOUNT_ID
        events.append(ev)

    return events


def generate_T1580_events(base_time: datetime, count: int) -> list:
    """
    T1580 - Cloud Infrastructure Discovery
    Tactic: Discovery

    Attack pattern simulated:
    - Rapid enumeration of AWS resources using list/describe API calls
    - All from same source IP within a very short time window (<3 minutes)
    - Covers IAM, EC2, S3, Lambda, RDS — breadth-first recon

    Detection signal:
    - High rate of distinct Describe*/List*/Get* API calls from single IP
    - Cross-service enumeration (IAM + EC2 + S3 + Lambda in same session)
    - No corresponding Create/Update events (pure recon, no action)
    """
    events = []
    user = ATTACKER_USER

    # Full enumeration toolkit — realistic tool like enumerate-iam or Pacu
    recon_calls = [
        ("GetCallerIdentity", "sts.amazonaws.com", {}, {"Account": ACCOUNT_ID, "UserId": "AIDA123"}),
        ("ListUsers", "iam.amazonaws.com", {}, {"Users": []}),
        ("ListRoles", "iam.amazonaws.com", {}, {"Roles": []}),
        ("ListGroups", "iam.amazonaws.com", {}, {"Groups": []}),
        ("ListPolicies", "iam.amazonaws.com", {"scope": "Local"}, {"Policies": []}),
        ("GetAccountAuthorizationDetails", "iam.amazonaws.com", {}, {}),
        ("ListAttachedUserPolicies", "iam.amazonaws.com", {"userName": ATTACKER_USER}, {}),
        ("DescribeInstances", "ec2.amazonaws.com", {}, {"Reservations": []}),
        ("DescribeSecurityGroups", "ec2.amazonaws.com", {}, {"SecurityGroups": []}),
        ("DescribeSubnets", "ec2.amazonaws.com", {}, {"Subnets": []}),
        ("DescribeVpcs", "ec2.amazonaws.com", {}, {"Vpcs": []}),
        ("DescribeKeyPairs", "ec2.amazonaws.com", {}, {"KeyPairs": []}),
        ("ListBuckets", "s3.amazonaws.com", {}, {"Buckets": [{"Name": S3_BUCKET}]}),
        ("ListFunctions", "lambda.amazonaws.com", {}, {"Functions": []}),
        ("DescribeDBInstances", "rds.amazonaws.com", {}, {"DBInstances": []}),
        ("ListTopics", "sns.amazonaws.com", {}, {"Topics": []}),
        ("ListQueues", "sqs.amazonaws.com", {}, {"QueueUrls": []}),
        ("DescribeLogGroups", "logs.amazonaws.com", {}, {"logGroups": []}),
        ("ListSecrets", "secretsmanager.amazonaws.com", {}, {"SecretList": []}),
        ("ListAliases", "kms.amazonaws.com", {}, {"Aliases": []}),
        ("DescribeTrails", "cloudtrail.amazonaws.com", {}, {"trailList": []}),
        ("GetBucketAcl", "s3.amazonaws.com", {"bucketName": S3_BUCKET}, {}),
        ("GetBucketPolicy", "s3.amazonaws.com", {"bucketName": S3_BUCKET}, {}),
        ("ListAccessKeys", "iam.amazonaws.com", {"userName": ATTACKER_USER}, {}),
        ("GetAccountPasswordPolicy", "iam.amazonaws.com", {}, {}),
    ]

    for i, (action, svc, req, resp) in enumerate(recon_calls[:count]):
        # All recon events happen within a 3-minute window — that's the detection signal
        t = make_timestamp(base_time, offset_seconds=10800 + i * 7)  # 7 seconds apart

        ev = base_event(
            event_name=action,
            source=svc,
            region="us-east-1",
            user=user,
            source_ip=ATTACKER_IPS[3],
            timestamp=t,
            request_params=req,
            response_elements=resp,
        )
        ev["mitreAttackTechnique"] = "T1580 - Cloud Infrastructure Discovery"
        ev["mitreAttackTactic"] = "Discovery"
        events.append(ev)

    return events


def generate_T1136_events(base_time: datetime, count: int) -> list:
    """
    T1136 - Create Account
    Tactic: Persistence

    Attack pattern simulated:
    - Attacker creates a new IAM user with a non-obvious name
    - Attaches AdministratorAccess policy to the new user (immediate privilege)
    - Creates access key for the new user (programmatic persistence)
    - No corresponding provisioning ticket context (out-of-band creation)

    Detection signal:
    - CreateUser followed immediately by AttachUserPolicy (AdministratorAccess)
    - CreateAccessKey for the same new user
    - userName pattern doesn't match corporate naming convention
    - All three events within seconds of each other from attacker IP
    """
    events = []
    user = ATTACKER_USER
    new_user = NEW_MALICIOUS_USER

    actions = [
        (
            "CreateUser",
            "iam.amazonaws.com",
            {"userName": new_user},
            {"user": {
                "path": "/",
                "userName": new_user,
                "userId": "AIDANEWUSER12345",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{new_user}",
                "createDate": make_timestamp(base_time, offset_seconds=14400)
            }}
        ),
        (
            "AttachUserPolicy",
            "iam.amazonaws.com",
            {
                "userName": new_user,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            None
        ),
        (
            "CreateAccessKey",
            "iam.amazonaws.com",
            {"userName": new_user},
            {"accessKey": {
                "userName": new_user,
                "accessKeyId": "AKIANEWKEY12345678",
                "status": "Active",
                "secretAccessKey": "REDACTED"
            }}
        ),
        (
            "CreateLoginProfile",
            "iam.amazonaws.com",
            {"userName": new_user, "passwordResetRequired": False},
            {"loginProfile": {"userName": new_user}}
        ),
        (
            "AddUserToGroup",
            "iam.amazonaws.com",
            {"userName": new_user, "groupName": "Administrators"},
            None
        ),
    ]

    for i, (action, svc, req, resp) in enumerate(actions[:count]):
        # These happen within 30 seconds of each other — tight cluster is the signal
        t = make_timestamp(base_time, offset_seconds=14400 + i * 10)

        ev = base_event(
            event_name=action,
            source=svc,
            region="us-east-1",
            user=user,
            source_ip=ATTACKER_IPS[0],
            timestamp=t,
            request_params=req,
            response_elements=resp,
        )
        ev["mitreAttackTechnique"] = "T1136 - Create Account"
        ev["mitreAttackTactic"] = "Persistence"
        events.append(ev)

    return events


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    # All events anchored to the same simulated "attack day"
    base_time = datetime(2024, 12, 15, 8, 0, 0, tzinfo=timezone.utc)

    all_events = []

    generators = {
        "T1078": generate_T1078_events,
        "T1530": generate_T1530_events,
        "T1537": generate_T1537_events,
        "T1580": generate_T1580_events,
        "T1136": generate_T1136_events,
    }

    for ttp, generator_fn in generators.items():
        print(f"[+] Generating {EVENTS_PER_TTP[ttp]} events for {ttp}...")
        events = generator_fn(base_time, EVENTS_PER_TTP[ttp])
        all_events.extend(events)
        print(f"    Done. {len(events)} events generated.")

    # Sort all events by eventTime so they appear in chronological order
    all_events.sort(key=lambda e: e["eventTime"])

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_FILE)), exist_ok=True)

    # Write NDJSON — one JSON object per line
    # This format is what both Splunk and Sentinel ingest natively
    with open(OUTPUT_FILE, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    print(f"\n[+] Total events written: {len(all_events)}")
    print(f"[+] Output file: {os.path.abspath(OUTPUT_FILE)}")
    print("\nEvent breakdown:")
    for ttp in generators:
        count = sum(1 for e in all_events if ttp in e.get("mitreAttackTechnique", ""))
        print(f"  {ttp}: {count} events")


if __name__ == "__main__":
    main()
