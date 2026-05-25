import { defineConfig } from "orval";

/**
 * Generate the typed API client from FastAPI's live OpenAPI spec.
 *
 * Usage:
 *   - Start the API (`just up`)
 *   - From `web/`: `pnpm gen-api`
 *
 * The generated files live under `src/api/` and are gitignored (regenerated
 * on every build in CI). Hand-rolled wrappers around the generated functions
 * live in `src/api/client.ts`.
 */
export default defineConfig({
  ippon: {
    input: {
      target:
        process.env.IPPON_OPENAPI_URL ?? "http://localhost:8000/openapi.json",
    },
    output: {
      target: "./src/api/generated.ts",
      schemas: "./src/api/model",
      client: "react-query",
      mode: "single",
      override: {
        mutator: {
          path: "./src/api/fetcher.ts",
          name: "fetcher",
        },
        query: {
          useQuery: true,
          useSuspenseQuery: false,
          signal: true,
        },
      },
    },
  },
});
