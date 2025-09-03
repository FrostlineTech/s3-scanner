# Frostline Red Team — S3 Misconfiguration Scanner

A read-focused S3 misconfiguration scanner:

- Lists publicly accessible buckets anonymously
- Optionally downloads readable objects
- Retrieves bucket ACLs
- Logs to timestamped files in logs/ and optionally JSONL

## Requirements (Kali Linux)

- Python 3 (preinstalled on Kali)
- AWS CLI
  Install:
    sudo apt update && sudo apt install -y awscli
  Verify:
    aws --version
No AWS credentials required; scanner uses `--no-sign-request`.

## Quick Start (Interactive)

python3 s3_scanner.py

# Enter a bucket name when prompted, or 'exit' to quit

## Non-Interactive Usage

Scan a single bucket and download files:
python3 s3_scanner.py --bucket my-public-bucket

List only (no downloads), write JSONL, verbose:
python3 s3_scanner.py --bucket my-public-bucket --no-download --json --verbose

Scan multiple buckets from a file:
python3 s3_scanner.py --buckets-file buckets.txt

Prefix + include filter, limit keys, 10s timeout:
python3 s3_scanner.py --bucket my-public-bucket --prefix logs/ --include "*.log" --limit 100 --timeout 10

Skip large files (>5MB):
python3 s3_scanner.py --bucket my-public-bucket --max-download-size 5242880

Anonymous write-test (uploads then deletes a marker):
python3 s3_scanner.py --bucket my-public-bucket --test-write

Change output directory (logs/ and downloads/ inside this path):
python3 s3_scanner.py --bucket my-public-bucket --output /tmp/frostline

Quiet mode:
python3 s3_scanner.py --bucket my-public-bucket --quiet

## Outputs

- Logs: logs/s3_audit_<timestamp>.log
- JSONL (if --json): logs/s3_audit_<timestamp>.log.jsonl
- Downloads: downloads/<bucket_name>/

## Exit Codes

- 0: no public buckets discovered and no errors
- 10: at least one public bucket discovered
- 1: errors occurred

## Troubleshooting (Kali)

- “AWS CLI not installed or not in PATH”
  Ensure `aws --version` works. Install with:
    sudo apt update && sudo apt install -y awscli
- Permission denied on downloads:
  Ensure the working directory is writable, or set `--output /path/you/own`.

## Legal

Use only with authorization. You are responsible for complying with all applicable laws and policies.
