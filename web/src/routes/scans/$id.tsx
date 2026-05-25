import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useState } from "react";

import {
  getScan,
  listFindings,
  type Finding,
  type Severity,
} from "@/api/client";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime, formatDuration } from "@/lib/utils";

export const Route = createFileRoute("/scans/$id")({
  component: ScanPage,
});

const columnHelper = createColumnHelper<Finding>();

const columns = [
  columnHelper.accessor("severity", {
    header: "Severity",
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
  }),
  columnHelper.accessor("cve_id", {
    header: "CVE",
    cell: (info) => (
      <span className="font-mono text-xs text-zinc-900">{info.getValue()}</span>
    ),
  }),
  columnHelper.accessor("name", {
    header: "Package",
    cell: (info) => <span className="text-zinc-900">{info.getValue()}</span>,
  }),
  columnHelper.accessor("version", {
    header: "Version",
    cell: (info) => <span className="text-zinc-600">{info.getValue()}</span>,
  }),
  columnHelper.accessor("fix_state", {
    header: "Fix",
    cell: (info) => <span className="text-zinc-500">{info.getValue()}</span>,
  }),
  columnHelper.accessor("cvss_score", {
    header: "CVSS",
    cell: (info) => {
      const v = info.getValue();
      return v == null ? <span className="text-zinc-400">—</span> : <span>{v.toFixed(1)}</span>;
    },
  }),
];

const SEVERITIES: Array<Severity | "all"> = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "negligible",
  "unknown",
];

const PAGE_SIZE = 50;

function ScanPage() {
  const { id } = Route.useParams();
  const [page, setPage] = useState(0);
  const [severity, setSeverity] = useState<Severity | "all">("all");

  const scanQuery = useQuery({
    queryKey: ["scan", id],
    queryFn: () => getScan(id),
    refetchInterval: (q) => {
      const status = q.state.data?.status;
      return status === "succeeded" || status === "failed" || status === "cancelled" ? false : 2000;
    },
  });

  const findingsQuery = useQuery({
    queryKey: ["findings", id, page, severity],
    queryFn: () =>
      listFindings({
        scanId: id,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        severity: severity === "all" ? undefined : severity,
      }),
    enabled: scanQuery.data?.status === "succeeded",
  });

  const table = useReactTable({
    data: findingsQuery.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  const scan = scanQuery.data;
  const total = findingsQuery.data?.total ?? 0;
  const showingFrom = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const showingTo = Math.min(total, (page + 1) * PAGE_SIZE);

  return (
    <section className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <Link to="/repos" className="text-sm text-zinc-500 hover:text-zinc-900">
            ← Repos
          </Link>
          <h1 className="mt-2 font-mono text-lg text-zinc-900">
            scan {id.slice(0, 8)}
            <span className="text-zinc-400">…</span>
          </h1>
        </div>
        {scan && <StatusBadge status={scan.status} />}
      </div>

      {scan && (
        <div className="grid grid-cols-2 gap-4 rounded-lg border border-zinc-200 bg-white p-5 shadow-sm sm:grid-cols-4">
          <Field label="Backend" value={scan.backend} />
          <Field label="Ref" value={scan.requested_ref} />
          <Field label="Commit" value={scan.resolved_commit_sha?.slice(0, 12) ?? "—"} mono />
          <Field label="Duration" value={formatDuration(scan.duration_seconds)} />
          <Field label="Syft" value={scan.syft_version ?? "—"} />
          <Field label="Grype" value={scan.grype_version ?? "—"} />
          <Field label="Started" value={formatDateTime(scan.started_at)} />
          <Field label="Finished" value={formatDateTime(scan.finished_at)} />
        </div>
      )}

      {scan?.error_message && (
        <div className="rounded-md border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-900">
          <span className="font-medium">error:</span> {scan.error_message}
        </div>
      )}

      <div className="flex items-center gap-2">
        <span className="text-sm text-zinc-500">Filter:</span>
        {SEVERITIES.map((s) => (
          <Button
            key={s}
            tone={severity === s ? "default" : "outline"}
            onClick={() => {
              setSeverity(s);
              setPage(0);
            }}
          >
            {s}
          </Button>
        ))}
      </div>

      <Table>
        <THead>
          {table.getHeaderGroups().map((hg) => (
            <TR key={hg.id}>
              {hg.headers.map((h) => (
                <TH key={h.id}>{flexRender(h.column.columnDef.header, h.getContext())}</TH>
              ))}
            </TR>
          ))}
        </THead>
        <TBody>
          {findingsQuery.isLoading && (
            <TR>
              <TD colSpan={columns.length} className="text-center text-zinc-400 py-8">
                loading…
              </TD>
            </TR>
          )}
          {!findingsQuery.isLoading && table.getRowModel().rows.length === 0 && (
            <TR>
              <TD colSpan={columns.length} className="text-center text-zinc-400 py-8">
                No findings.
              </TD>
            </TR>
          )}
          {table.getRowModel().rows.map((row) => (
            <TR key={row.id}>
              {row.getVisibleCells().map((cell) => (
                <TD key={cell.id}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TD>
              ))}
            </TR>
          ))}
        </TBody>
      </Table>

      <div className="flex items-center justify-between text-sm">
        <p className="text-zinc-500">
          {total === 0 ? "0 findings" : `${showingFrom}–${showingTo} of ${total}`}
        </p>
        <div className="flex gap-2">
          <Button
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            Previous
          </Button>
          <Button
            disabled={showingTo >= total}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      </div>
    </section>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
      <div className={mono ? "font-mono text-sm text-zinc-900" : "text-sm text-zinc-900"}>
        {value}
      </div>
    </div>
  );
}
