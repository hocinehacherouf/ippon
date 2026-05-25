import { createRootRoute, Link, Outlet } from "@tanstack/react-router";

export const Route = createRootRoute({
  component: RootLayout,
});

function RootLayout() {
  return (
    <div className="min-h-dvh">
      <header className="border-b border-zinc-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <Link
            to="/repos"
            className="flex items-center gap-2 text-base font-semibold text-zinc-900"
          >
            <span className="rounded-md bg-zinc-900 px-2 py-0.5 text-xs font-mono text-white">
              ippon
            </span>
            <span className="text-zinc-500">SBOM + CVE scanner</span>
          </Link>
          <nav className="flex items-center gap-4 text-sm">
            <Link
              to="/repos"
              activeProps={{ className: "text-zinc-900 font-medium" }}
              inactiveProps={{ className: "text-zinc-500 hover:text-zinc-900" }}
            >
              Repos
            </Link>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
