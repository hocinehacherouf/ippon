import { cva, type VariantProps } from "class-variance-authority";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
  {
    variants: {
      tone: {
        neutral: "bg-zinc-100 text-zinc-700 ring-zinc-300",
        critical: "bg-rose-100 text-rose-900 ring-rose-300",
        high: "bg-orange-100 text-orange-900 ring-orange-300",
        medium: "bg-amber-100 text-amber-900 ring-amber-300",
        low: "bg-emerald-100 text-emerald-900 ring-emerald-300",
        info: "bg-sky-100 text-sky-900 ring-sky-300",
        success: "bg-emerald-100 text-emerald-900 ring-emerald-300",
        failed: "bg-rose-100 text-rose-900 ring-rose-300",
        running: "bg-sky-100 text-sky-900 ring-sky-300",
        muted: "bg-zinc-50 text-zinc-500 ring-zinc-200",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps
  extends VariantProps<typeof badgeVariants> {
  children: ReactNode;
  className?: string;
}

export function Badge({ tone, children, className }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)}>{children}</span>;
}

const SEVERITY_TONE = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  negligible: "muted",
  unknown: "muted",
} as const;

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase() as keyof typeof SEVERITY_TONE;
  const tone = SEVERITY_TONE[key] ?? "muted";
  return <Badge tone={tone}>{severity}</Badge>;
}

const STATUS_TONE = {
  pending: "muted",
  queued: "info",
  running: "running",
  succeeded: "success",
  failed: "failed",
  cancelled: "muted",
} as const;

export function StatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <Badge tone="muted">—</Badge>;
  const tone = STATUS_TONE[status as keyof typeof STATUS_TONE] ?? "neutral";
  return <Badge tone={tone}>{status}</Badge>;
}
