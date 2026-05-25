"""CLI: ``python -m ippon.scripts.scan <REPO> [REF]``.

Thin client over the API: POST /scans → poll /scans/{id} until terminal.
Exits non-zero if the scan ends in ``failed``. Used by ``just scan REPO=…``.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import httpx

DEFAULT_BASE_URL = "http://localhost:8000"
TERMINAL_STATES = {"succeeded", "failed", "cancelled"}


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ippon-scan", description="Trigger and watch an ippon scan."
    )
    parser.add_argument("repo", help="HTTPS clone URL")
    parser.add_argument("ref", nargs="?", default="HEAD", help="Branch, tag, or commit sha")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("IPPON_API_BASE", DEFAULT_BASE_URL),
        help="API base URL (env: IPPON_API_BASE)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("IPPON_DEV_TOKEN", "dev-token-replace-me"),
        help="Bearer token (env: IPPON_DEV_TOKEN)",
    )
    parser.add_argument("--timeout", type=int, default=180, help="Total wall-clock budget, seconds")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between polls")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    headers = {"Authorization": f"Bearer {args.token}"}
    with httpx.Client(base_url=args.base_url, headers=headers, timeout=30.0) as client:
        print(f"POST {args.base_url}/scans repo={args.repo} ref={args.ref}")
        r = client.post("/scans", json={"repo_url": args.repo, "ref": args.ref})
        if r.status_code >= 400:
            print(f"create scan failed: HTTP {r.status_code} {r.text}", file=sys.stderr)
            return 1
        scan = r.json()
        scan_id = scan["id"]
        print(f"scan_id={scan_id} status={scan['status']}")

        deadline = time.monotonic() + args.timeout
        last_status = scan["status"]
        while time.monotonic() < deadline:
            time.sleep(args.poll_interval)
            r = client.get(f"/scans/{scan_id}")
            if r.status_code >= 400:
                print(f"poll failed: HTTP {r.status_code} {r.text}", file=sys.stderr)
                return 2
            cur = r.json()
            if cur["status"] != last_status:
                print(f"  → {cur['status']}")
                last_status = cur["status"]
            if cur["status"] in TERMINAL_STATES:
                print()
                print("== final ==")
                for k in (
                    "status",
                    "resolved_commit_sha",
                    "syft_version",
                    "grype_version",
                    "sbom_object_key",
                    "sbom_sha256",
                    "duration_seconds",
                    "error_message",
                ):
                    if cur.get(k) is not None:
                        print(f"  {k}: {cur[k]}")
                return 0 if cur["status"] == "succeeded" else 3

        print(f"timed out after {args.timeout}s (last status={last_status})", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
