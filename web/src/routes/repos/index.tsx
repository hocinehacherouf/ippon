import { useQuery } from "@tanstack/react-query";
import {
  createFileRoute,
  Link,
} from "@tanstack/react-router";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { listRepos, type RepositoryListItem } from "@/api/client";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { formatDateTime, formatDuration } from "@/lib/utils";

export const Route = createFileRoute("/repos/")({
  component: ReposPage,
});

const columnHelper = createColumnHelper<RepositoryListItem>();

const columns = [
  columnHelper.accessor("full_name", {
    header: "Repository",
    cell: (info) => (
      <span className="font-mono text-zinc-900">{info.getValue()}</span>
    ),
  }),
  columnHelper.accessor("default_branch", {
    header: "Branch",
    cell: (info) => <span className="text-zinc-600">{info.getValue()}</span>,
  }),
  columnHelper.accessor("last_scan_status", {
    header: "Last Scan",
    cell: (info) => <StatusBadge status={info.getValue() ?? undefined} />,
  }),
  columnHelper.accessor("last_scan_finished_at", {
    header: "Finished",
    cell: (info) => (
      <span className="text-zinc-500">{formatDateTime(info.getValue())}</span>
    ),
  }),
  columnHelper.accessor("last_scan_duration_seconds", {
    header: "Duration",
    cell: (info) => (
      <span className="text-zinc-500">{formatDuration(info.getValue())}</span>
    ),
  }),
  columnHelper.display({
    id: "actions",
    header: "",
    cell: ({ row }) => {
      const scanId = row.original.last_scan_id;
      if (!scanId) return <span className="text-zinc-400">—</span>;
      return (
        <Link
          to="/scans/$id"
          params={{ id: scanId }}
          className="text-sm font-medium text-sky-700 hover:text-sky-900"
        >
          View scan →
        </Link>
      );
    },
  }),
];

function ReposPage() {
  const query = useQuery({
    queryKey: ["repos"],
    queryFn: listRepos,
    refetchInterval: 5000,
  });

  const table = useReactTable({
    data: query.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <section className="space-y-4">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-zinc-900">Repositories</h1>
          <p className="mt-1 text-sm text-zinc-500">
            {query.data
              ? `${query.data.total} registered`
              : query.isLoading
                ? "loading…"
                : ""}
          </p>
        </div>
      </div>

      {query.isError && (
        <div className="rounded-md border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-900">
          {(query.error as Error).message}
        </div>
      )}

      <Table>
        <THead>
          {table.getHeaderGroups().map((hg) => (
            <TR key={hg.id}>
              {hg.headers.map((h) => (
                <TH key={h.id}>
                  {flexRender(h.column.columnDef.header, h.getContext())}
                </TH>
              ))}
            </TR>
          ))}
        </THead>
        <TBody>
          {table.getRowModel().rows.length === 0 && !query.isLoading && (
            <TR>
              <TD colSpan={columns.length} className="text-center text-zinc-400 py-8">
                No repositories yet. Run{" "}
                <code className="rounded bg-zinc-100 px-1.5 py-0.5 text-xs">
                  just scan https://github.com/anchore/syft
                </code>{" "}
                to register one.
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
    </section>
  );
}
