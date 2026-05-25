import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center rounded-md text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      tone: {
        default: "bg-zinc-900 text-white hover:bg-zinc-800",
        outline: "border border-zinc-300 bg-white text-zinc-900 hover:bg-zinc-50",
        ghost: "text-zinc-700 hover:bg-zinc-100",
      },
      size: {
        sm: "h-7 px-3",
        md: "h-8 px-4",
      },
    },
    defaultVariants: { tone: "outline", size: "sm" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export function Button({ className, tone, size, ...props }: ButtonProps) {
  return <button className={cn(buttonVariants({ tone, size }), className)} {...props} />;
}
