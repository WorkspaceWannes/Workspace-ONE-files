import os
import csv
import io
from datetime import datetime, timezone

import requests
from google.cloud import bigquery


# --------- config helpers --------- #

def get_config():
    """Read required config from environment variables."""
    cfg = {
        "INTEL_CLIENT_ID": os.environ.get("INTEL_CLIENT_ID"),
        "INTEL_CLIENT_SECRET": os.environ.get("INTEL_CLIENT_SECRET"),
        "INTEL_TENANT_HOST": os.environ.get("INTEL_TENANT_HOST"),
        "INTEL_REPORT_ID": os.environ.get("INTEL_REPORT_ID"),
        "BQ_PROJECT_ID": os.environ.get("BQ_PROJECT_ID"),
        "BQ_DATASET": os.environ.get("BQ_DATASET"),
        "BQ_TABLE": os.environ.get("BQ_TABLE"),
    }
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")
    return cfg


_bq_client = None


def get_bq_client(project_id: str) -> bigquery.Client:
    """Singleton BigQuery client."""
    global _bq_client
    if _bq_client is None:
        _bq_client = bigquery.Client(project=project_id)
    return _bq_client


# --------- Workspace ONE Intelligence helpers --------- #

def get_intel_token(cfg: dict) -> str:
    """Get OAuth token for WS1 Intelligence service account."""
    url = f"https://auth.{cfg['INTEL_TENANT_HOST']}/oauth/token"
    data = {
        "client_id": cfg["INTEL_CLIENT_ID"],
        "client_secret": cfg["INTEL_CLIENT_SECRET"],
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_latest_download_id(cfg: dict, token: str) -> str:
    """
    Call WS1 Reports API to get the latest COMPLETED download id
    for the configured report.
    """
    base_api = f"https://api.{cfg['INTEL_TENANT_HOST']}"
    url = f"{base_api}/v1/reports/{cfg['INTEL_REPORT_ID']}/downloads/search"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {
        "offset": 0,
        "page_size": 50,
    }

    resp = requests.post(url, headers=headers, json=body, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    results = data.get("data", {}).get("results", [])
    completed = [r for r in results if r.get("status") == "COMPLETED"]

    if not completed:
        raise RuntimeError("No COMPLETED downloads found for this report")

    # Take most recently modified COMPLETED download
    latest = sorted(
        completed,
        key=lambda r: r.get("modified_at", ""),
        reverse=True,
    )[0]

    return latest["id"]


def download_csv_bytes(cfg: dict, token: str, download_id: str) -> bytes:
    """Download CSV file for a given download id."""
    base_api = f"https://api.{cfg['INTEL_TENANT_HOST']}"
    url = f"{base_api}/v1/reports/tracking/{download_id}/download"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "*/*",
    }

    resp = requests.get(url, headers=headers, timeout=300)
    resp.raise_for_status()
    return resp.content


# --------- BigQuery loader (append snapshots) --------- #

def load_csv_snapshot_to_bigquery(cfg: dict, csv_bytes: bytes) -> str:
    """
    Parse CSV, add snapshot_timestamp to each row and append to BigQuery table.

    This keeps history: every function run adds a new snapshot.
    """
    project_id = cfg["BQ_PROJECT_ID"]
    dataset = cfg["BQ_DATASET"]
    table = cfg["BQ_TABLE"]
    table_id = f"{project_id}.{dataset}.{table}"

    # decode CSV
    text_stream = io.StringIO(csv_bytes.decode("utf-8"))
    reader = csv.DictReader(text_stream)

    # timestamp for this snapshot (UTC ISO string)
    snapshot_ts = datetime.now(timezone.utc).isoformat()

    rows = []
    for row in reader:
        # skip completely empty lines
        if not any(row.values()):
            continue
        row["snapshot_timestamp"] = snapshot_ts
        rows.append(row)

    if not rows:
        # no data rows in CSV (e.g. no active devices)
        return f"No data rows in CSV; nothing appended to {table_id}"

    client = get_bq_client(project_id)

    job_config = bigquery.LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        autodetect=True,
        schema_update_options=[
            bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION
        ],
    )

    load_job = client.load_table_from_json(
        rows,
        table_id,
        job_config=job_config,
    )
    load_job.result()  # wait for completion

    return f"Loaded {len(rows)} rows into {table_id}"


# --------- HTTP entrypoint --------- #

def main(request):
    """
    HTTP entrypoint for Cloud Run function.

    - Reads config from env
    - Gets WS1 token
    - Finds latest report download
    - Downloads CSV
    - Appends snapshot rows to BigQuery
    """
    try:
        cfg = get_config()

        token = get_intel_token(cfg)
        download_id = get_latest_download_id(cfg, token)
        csv_bytes = download_csv_bytes(cfg, token, download_id)

        msg = load_csv_snapshot_to_bigquery(cfg, csv_bytes)
        return (f"OK: {msg}", 200)

    except Exception as e:
        # Return the error text; Cloud Run logs will have full traceback
        return (f"Error: {e}", 500)
