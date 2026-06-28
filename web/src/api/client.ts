/**
 * Hand-rolled wrappers around the two API surfaces M8 needs.
 *
 * Once ``pnpm gen-api`` runs successfully, this file can be replaced by the
 * orval-generated hooks. We keep it hand-rolled for now so the UI can be
 * built and verified without a running API at codegen time.
 */

import { fetcher } from "./fetcher";

export type ScanJobStatus =
  | "pending"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface RepositoryListItem {
  id: string;
  org_id: string;
  full_name: string;
  clone_url: string;
  default_branch: string;
  is_archived: boolean;
  last_scanned_at: string | null;
  last_scan_id: string | null;
  last_scan_status: ScanJobStatus | null;
  last_scan_finished_at: string | null;
  last_scan_duration_seconds: number | null;
}

export interface RepositoryList {
  items: RepositoryListItem[];
  total: number;
}

export interface ScanResponse {
  id: string;
  org_id: string;
  repository_id: string;
  status: ScanJobStatus;
  backend: "docker" | "k8s" | "inline";
  requested_ref: string;
  resolved_commit_sha: string | null;
  syft_version: string | null;
  grype_version: string | null;
  grype_db_version: string | null;
  sbom_object_key: string | null;
  sbom_sha256: string | null;
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
  attempt: number;
}

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "negligible"
  | "unknown";

export interface Finding {
  scan_id: string;
  cve_id: string;
  purl: string;
  name: string;
  version: string;
  severity: Severity;
  fix_state: string;
  fix_versions: string[];
  description: string;
  cvss_score: number | null;
  cvss_vector: string;
  matcher: string;
  scanned_at: string;
}

export interface FindingPage {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
}

export type ValidationStatus = "verified" | "unverified" | "unknown" | "error";

export interface SecretFinding {
  scan_id: string;
  rule_id: string;
  description: string;
  file: string;
  start_line: number;
  end_line: number;
  match: string;
  fingerprint: string;
  author: string;
  email: string;
  committed_at: string | null;
  tags: string[];
  verified: boolean;
  validation_status: ValidationStatus;
  is_historical: boolean;
  scanned_at: string;
}

export interface SecretFindingPage {
  items: SecretFinding[];
  total: number;
  limit: number;
  offset: number;
}

export function listRepos(): Promise<RepositoryList> {
  return fetcher<RepositoryList>({ url: "/repos", method: "GET" });
}

export function getScan(scanId: string): Promise<ScanResponse> {
  return fetcher<ScanResponse>({ url: `/scans/${scanId}`, method: "GET" });
}

export interface ListFindingsArgs {
  scanId: string;
  limit?: number;
  offset?: number;
  severity?: Severity;
}

export function listFindings(args: ListFindingsArgs): Promise<FindingPage> {
  return fetcher<FindingPage>({
    url: `/scans/${args.scanId}/findings`,
    method: "GET",
    params: {
      limit: args.limit,
      offset: args.offset,
      severity: args.severity,
    },
  });
}

export interface ListSecretsArgs {
  scanId: string;
  limit?: number;
  offset?: number;
  validationStatus?: ValidationStatus;
}

export function listSecrets(args: ListSecretsArgs): Promise<SecretFindingPage> {
  return fetcher<SecretFindingPage>({
    url: `/scans/${args.scanId}/secrets`,
    method: "GET",
    params: {
      limit: args.limit,
      offset: args.offset,
      validation_status: args.validationStatus,
    },
  });
}
