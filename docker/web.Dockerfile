# syntax=docker/dockerfile:1.7
#
# Frontend image. Two stages on Wolfi:
#
#   1. ``deps``: install pnpm, hydrate node_modules — cached layer.
#   2. ``dev``: the only target compose builds; runs ``pnpm dev`` with
#      HMR via a bind-mount over ``/app``.
#
# A production stage (``build`` + nginx) is straightforward to add when
# we need it; the scaffold only ships the dev server.

FROM cgr.dev/chainguard/wolfi-base@sha256:b78bb982194828b6c9c214230bf34d51944e2102ea8468f01ac21e5f99328efd AS deps

RUN apk add --no-cache nodejs-22 pnpm

WORKDIR /app

COPY web/package.json web/pnpm-lock.yaml /app/

RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

# ---

FROM cgr.dev/chainguard/wolfi-base@sha256:b78bb982194828b6c9c214230bf34d51944e2102ea8468f01ac21e5f99328efd AS dev

# ``wget`` is what compose's healthcheck uses to probe the dev server.
RUN apk add --no-cache nodejs-22 pnpm wget \
    && addgroup -g 1000 -S appgroup \
    && adduser -S appuser -u 1000 -G appgroup

WORKDIR /app

COPY --from=deps --chown=appuser:appgroup /app/node_modules /app/node_modules
COPY --chown=appuser:appgroup web /app

USER appuser

ENV NODE_ENV=development \
    HOST=0.0.0.0 \
    PORT=5173

EXPOSE 5173

CMD ["pnpm", "dev"]
