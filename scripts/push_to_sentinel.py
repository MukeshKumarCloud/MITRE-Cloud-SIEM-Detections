"""
push_to_sentinel.py
--------------------
Pushes the generated CloudTrail logs to Microsoft Sentinel via the
Azure Monitor Logs Ingestion API.

SECURITY NOTE: Before committing this file to git, make sure the values
below are placeholders, not your real credentials. See README.md Phase 5,
Step 5.2 for the full explanation of why this matters.

Install dependencies first:
  pip3 install azure-identity azure-monitor-ingestion --break-system-packages

Usage:
  python3 push_to_sentinel.py
"""

import json
import os
from azure.identity import ClientSecretCredential
from azure.monitor.ingestion import LogsIngestionClient

# ─────────────────────────────────────────────────────────────
# CONFIGURATION — fill these in from your Azure setup (README Step 4.5)
# DO NOT commit real values here. Use environment variables instead
# if you want to actually run this against your Azure tenant:
#   export AZURE_TENANT_ID="..."
#   export AZURE_CLIENT_ID="..."
#   export AZURE_CLIENT_SECRET="..."
#   export DCE_ENDPOINT="..."
#   export DCR_IMMUTABLE_ID="..."
# ─────────────────────────────────────────────────────────────

TENANT_ID = os.environ.get("AZURE_TENANT_ID", "YOUR_TENANT_ID")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "YOUR_APP_REGISTRATION_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
DCE_ENDPOINT = os.environ.get("DCE_ENDPOINT", "YOUR_DCE_LOGS_INGESTION_URL")
DCR_IMMUTABLE_ID = os.environ.get("DCR_IMMUTABLE_ID", "YOUR_DCR_IMMUTABLE_ID")
STREAM_NAME = "Custom-CloudTrailLab_CL"  # Custom- prefix is required by the API

LOGS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "sample-logs", "sample_cloudtrail_logs.json"
)

BATCH_SIZE = 50  # API accepts batches — push in chunks


def main():
    if "YOUR_" in TENANT_ID or "YOUR_" in CLIENT_ID:
        print("[!] Placeholder credentials detected.")
        print("[!] Set environment variables before running, see header comment.")
        print("[!] Refusing to run with placeholder values.")
        return

    credential = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )

    with open(LOGS_FILE, "r") as f:
        logs = [json.loads(line) for line in f if line.strip()]

    print(f"[+] Loaded {len(logs)} events from {LOGS_FILE}")

    with LogsIngestionClient(endpoint=DCE_ENDPOINT, credential=credential) as client:
        for i in range(0, len(logs), BATCH_SIZE):
            batch = logs[i:i + BATCH_SIZE]
            try:
                client.upload(rule_id=DCR_IMMUTABLE_ID, stream_name=STREAM_NAME, logs=batch)
                print(f"[+] Uploaded batch {i // BATCH_SIZE + 1}: {len(batch)} events")
            except Exception as e:
                print(f"[!] Batch {i // BATCH_SIZE + 1} FAILED: {type(e).__name__}: {e}")
                print("[!] Common causes:")
                print("    - DCR_IMMUTABLE_ID or DCE_ENDPOINT is wrong (copy-paste error)")
                print("    - App registration doesn't have 'Monitoring Metrics Publisher'")
                print("      role assigned on the DCR yet (check README Step 4.5, item 4)")
                print("    - STREAM_NAME doesn't match what the DCR's stream declaration")
                print("      expects (must be 'Custom-CloudTrailLab_CL' exactly)")
                print("    - A field in this batch doesn't match the DCR transform's")
                print("      expected input schema")
                print("[!] Stopping here rather than continuing to push more batches")
                print("[!] blind into a confirmed-broken pipeline.")
                raise

    print(f"\n[+] Total events uploaded: {len(logs)}")
    print("[+] Wait a few minutes, then query CloudTrailLab_CL in Sentinel Logs.")


if __name__ == "__main__":
    main()
