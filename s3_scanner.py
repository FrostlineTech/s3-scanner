import subprocess
import sys
import os
import datetime
import argparse
import json
import time
import tempfile
import fnmatch

LOG_DIR = "logs"
DOWNLOAD_DIR = "downloads"

def frostline_banner():
    banner = r"""
   ______             _   _ _            
  |  ____|           | | (_) |           
  | |__ _ __ ___  ___| |_ _| | ___ _ __  
  |  __| '__/ _ \/ __| __| | |/ _ \ '_ \ 
  | |  | | | (_) \__ \ |_| | |  __/ | | |
  |_|  |_|  \___/|___/\__|_|_|\___|_| |_|                                          
     F R O S T L I N E   R E D   T E A M
    -------------------------------------
         S3 Misconfiguration Scanner
    """
    print(banner)
    print()

def run_command(cmd, timeout=30):
    """Run a shell command safely and return output or error."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out.", 1
    except FileNotFoundError:
        return "", "AWS CLI not installed or not in PATH.", 1
    except Exception as e:
        return "", f"Unexpected error: {e}", 1

def aws_with_retries(cmd, retries=2, base_delay=1.0, timeout=30):
    """Execute an aws cli command with simple retries/backoff."""
    attempt = 0
    while True:
        stdout, stderr, code = run_command(cmd, timeout=timeout)
        if code == 0:
            return stdout, stderr, code
        attempt += 1
        if attempt > retries:
            return stdout, stderr, code
        time.sleep(base_delay * (2 ** (attempt - 1)))

def ensure_dirs(base_output_dir):
    logs_dir = os.path.join(base_output_dir, LOG_DIR)
    downloads_dir = os.path.join(base_output_dir, DOWNLOAD_DIR)
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(downloads_dir, exist_ok=True)
    return logs_dir, downloads_dir

class Reporter:
    def __init__(self, log_path, jsonl=False, quiet=False):
        self.log_path = log_path
        self.jsonl = jsonl
        self.quiet = quiet
        self._fh = open(self.log_path, "a", encoding="utf-8")
        self._jsonl_fh = None
        if self.jsonl:
            self._jsonl_fh = open(self.log_path + ".jsonl", "a", encoding="utf-8")

    def close(self):
        try:
            self._fh.close()
        finally:
            if self._jsonl_fh:
                self._jsonl_fh.close()

    def log(self, text=""):
        self._fh.write(text + "\n")
        self._fh.flush()
        if not self.quiet and text:
            print(text)

    def event(self, obj):
        if self._jsonl_fh:
            self._jsonl_fh.write(json.dumps(obj) + "\n")
            self._jsonl_fh.flush()

def parse_ls(stdout):
    """Parse 'aws s3 ls --recursive' output to list of dicts with size and key."""
    items = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Expected: 2020-01-01 00:00:00      1234 some/key
        parts = line.split()
        if len(parts) >= 4:
            try:
                size = int(parts[2])
            except ValueError:
                size = None
            key = " ".join(parts[3:])
            items.append({"size": size, "key": key})
        else:
            # Sometimes directories show up; skip
            continue
    return items

def check_bucket(bucket_name, reporter, downloads_base, args):
    summary = {
        "bucket": bucket_name,
        "public": False,
        "file_count": 0,
        "downloaded": 0,
        "errors": [],
        "write_test": None,
    }

    reporter.log(f"\n=== Checking bucket: {bucket_name} ===")
    bucket_download_dir = os.path.join(downloads_base, bucket_name)
    os.makedirs(bucket_download_dir, exist_ok=True)

    ls_cmd = [
        "aws", "s3", "ls", f"s3://{bucket_name}/{args.prefix if args.prefix else ''}",
        "--recursive", "--no-sign-request",
    ]

    stdout, stderr, code = aws_with_retries(ls_cmd, retries=2, timeout=args.timeout)
    if code == 0 and stdout:
        summary["public"] = True
        reporter.log(f"[+] Bucket '{bucket_name}' is PUBLICLY ACCESSIBLE!")
        items = parse_ls(stdout)
        # Filters
        if args.include:
            patterns = args.include
            items = [i for i in items if any(fnmatch.fnmatch(i["key"], p) for p in patterns)]
        if args.exclude:
            patterns = args.exclude
            items = [i for i in items if not any(fnmatch.fnmatch(i["key"], p) for p in patterns)]
        if args.max_download_size is not None:
            items = [i for i in items if i["size"] is None or i["size"] <= args.max_download_size]
        if args.limit is not None and args.limit > 0:
            items = items[: args.limit]

        summary["file_count"] = len(items)
        if items:
            if not args.quiet:
                reporter.log(f"[*] Found {len(items)} files.")
            if not args.no_download:
                reporter.log(f"[*] Downloading to {bucket_download_dir} ...")
                for i in items:
                    key = i["key"]
                    dest_path = os.path.join(bucket_download_dir, key)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    cp_cmd = [
                        "aws", "s3", "cp", f"s3://{bucket_name}/{key}", dest_path, "--no-sign-request"
                    ]
                    stdout_dl, stderr_dl, code_dl = aws_with_retries(cp_cmd, retries=1, timeout=args.timeout)
                    if code_dl == 0:
                        summary["downloaded"] += 1
                        reporter.log(f"    [+] {key}")
                    else:
                        msg = f"Failed to download {key}: {stderr_dl}"
                        summary["errors"].append(msg)
                        if args.verbose:
                            reporter.log("    [-] " + msg)
            else:
                reporter.log("[*] Skipping downloads (--no-download)")
        else:
            reporter.log("[-] No files found (after filters).")

        # Step 2: Enumerate ACLs
        reporter.log("[*] Enumerating bucket ACLs...")
        stdout_acl, stderr_acl, code_acl = aws_with_retries(
            ["aws", "s3api", "get-bucket-acl", "--bucket", bucket_name, "--no-sign-request"],
            retries=1,
            timeout=args.timeout,
        )
        if code_acl == 0:
            reporter.log("[+] Bucket ACLs retrieved:")
            reporter.log(stdout_acl)
            reporter.event({"bucket": bucket_name, "acls": stdout_acl})
        else:
            reporter.log("[-] Failed to retrieve ACLs.")
            summary["errors"].append(f"ACL error: {stderr_acl}")
    else:
        reporter.log(f"[-] Bucket '{bucket_name}' is not publicly listable.")
        if stderr:
            summary["errors"].append(stderr)

    # Optional write-test
    if args.test_write:
        reporter.log("[*] Performing anonymous write-test (opt-in)...")
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
            tf.write("frostline_write_test\n")
            tf_path = tf.name
        key_name = f"frostline_write_test_{int(time.time())}.txt"
        try:
            up_cmd = ["aws", "s3", "cp", tf_path, f"s3://{bucket_name}/{key_name}", "--no-sign-request"]
            so, se, rc = aws_with_retries(up_cmd, retries=0, timeout=args.timeout)
            if rc == 0:
                summary["write_test"] = True
                reporter.log(f"[!] WRITE POSSIBLE: uploaded {key_name}")
                # Try cleanup
                rm_cmd = ["aws", "s3", "rm", f"s3://{bucket_name}/{key_name}", "--no-sign-request"]
                aws_with_retries(rm_cmd, retries=0, timeout=args.timeout)
            else:
                summary["write_test"] = False
                if args.verbose:
                    reporter.log(f"[-] Write failed: {se}")
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass

    reporter.event({
        "bucket": bucket_name,
        "public": summary["public"],
        "file_count": summary["file_count"],
        "downloaded": summary["downloaded"],
        "errors": summary["errors"],
        "write_test": summary["write_test"],
    })
    return summary

def build_arg_parser():
    p = argparse.ArgumentParser(description="Frostline S3 Misconfiguration Scanner")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--bucket", help="Single bucket name to scan")
    g.add_argument("--buckets-file", help="Path to file with one bucket per line")
    p.add_argument("--no-download", action="store_true", help="Only enumerate, do not download")
    p.add_argument("--timeout", type=int, default=30, help="AWS CLI command timeout seconds (default 30)")
    p.add_argument("--output", default=".", help="Base output directory (default current dir)")
    p.add_argument("--json", action="store_true", help="Write structured .jsonl alongside .log")
    p.add_argument("--test-write", action="store_true", help="Attempt anonymous write (upload then delete marker)")
    p.add_argument("--max-download-size", type=int, help="Max size in bytes for downloads")
    p.add_argument("--include", nargs="*", help="Only include keys matching these glob patterns")
    p.add_argument("--exclude", nargs="*", help="Exclude keys matching these glob patterns")
    p.add_argument("--prefix", help="Only list keys under this prefix")
    p.add_argument("--limit", type=int, help="Limit number of keys to process")
    p.add_argument("--quiet", action="store_true", help="Reduce console output")
    p.add_argument("--verbose", action="store_true", help="Verbose console output")
    return p

def interactive_mode():
    logs_dir, downloads_dir = ensure_dirs(".")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(logs_dir, f"s3_audit_{timestamp}.log")
    frostline_banner()
    reporter = Reporter(log_file, jsonl=False, quiet=False)
    reporter.log(f"[*] Logging results to {log_file}\n")
    try:
        while True:
            bucket_name = input("Enter an S3 bucket name (or 'exit' to quit): ").strip()
            if bucket_name.lower() == "exit":
                reporter.log("Exiting Frostline Red Team tool.")
                break
            elif bucket_name:
                # default args for interactive
                class A: pass
                A.no_download = False
                A.timeout = 30
                A.prefix = None
                A.include = None
                A.exclude = None
                A.max_download_size = None
                A.limit = None
                A.test_write = False
                A.quiet = False
                A.verbose = False
                summary = check_bucket(bucket_name, reporter, downloads_dir, A)
                reporter.log(f"Summary: public={summary['public']}, files={summary['file_count']}, downloaded={summary['downloaded']}")
            else:
                reporter.log("Please enter a valid bucket name.")
    finally:
        reporter.close()

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # Non-interactive flow if bucket(s) provided; else interactive
    if not args.bucket and not args.buckets_file:
        interactive_mode()
        return

    logs_dir, downloads_dir = ensure_dirs(args.output)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(logs_dir, f"s3_audit_{timestamp}.log")

    if not args.quiet:
        frostline_banner()
    reporter = Reporter(log_file, jsonl=args.json, quiet=args.quiet)
    reporter.log(f"[*] Logging results to {log_file}")

    # Gather buckets
    buckets = []
    if args.bucket:
        buckets.append(args.bucket.strip())
    if args.buckets_file:
        try:
            with open(args.buckets_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    name = line.strip()
                    if name:
                        buckets.append(name)
        except Exception as e:
            reporter.log(f"[-] Failed to read buckets file: {e}")
            reporter.close()
            sys.exit(1)

    found_public = False
    had_errors = False
    totals = {"buckets": 0, "public": 0, "files": 0, "downloaded": 0}

    try:
        for b in buckets:
            totals["buckets"] += 1
            summary = check_bucket(b, reporter, downloads_dir, args)
            if summary["public"]:
                found_public = True
                totals["public"] += 1
            if summary["errors"]:
                had_errors = True
            totals["files"] += summary["file_count"]
            totals["downloaded"] += summary["downloaded"]

        reporter.log("\n=== Run Summary ===")
        reporter.log(f"Buckets scanned: {totals['buckets']}")
        reporter.log(f"Public buckets: {totals['public']}")
        reporter.log(f"Total files listed: {totals['files']}")
        reporter.log(f"Total files downloaded: {totals['downloaded']}")
    finally:
        reporter.close()

    # Exit codes: 0 OK (no public), 10 public found, 1 had errors
    if had_errors:
        sys.exit(1)
    if found_public:
        sys.exit(10)
    sys.exit(0)

if __name__ == "__main__":
    main()
