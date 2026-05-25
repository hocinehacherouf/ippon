# syntax=docker/dockerfile:1.7
#
# Frontend image. Two stages:
#   1. ``deps``: install pnpm, hydrate node_modules — cached layer.
#   2. ``dev``: run ``vite dev`` (used by compose; mounts ``web/`` over the
#      build context so HMR works against the host's editor).
#
# A production stage (``build`` + nginx) is straightforward to add later;
# the scaffold only needs the dev server.

FROM node:22-alpine AS deps

ENV PNPM_HOME=/pnpm
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

WORKDIR /app

COPY web/package.json web/pnpm-lock.yaml* /app/
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile || pnpm install

# ---

FROM deps AS dev
COPY web /app
EXPOSE 5173
CMD ["pnpm", "dev"]
