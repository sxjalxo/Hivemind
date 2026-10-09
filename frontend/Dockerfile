# The React dashboard, built and served by its own Nitro server.
#
# This is a TanStack Start app, not a static SPA: the build emits
# `.output/server/index.mjs` under the `node-server` preset, so the runtime
# stage is Node rather than a static file server. That is also the reason a
# Tauri shell would not be a drop-in -- Tauri wants static assets, and getting
# them would mean moving this app to SPA mode and reworking Clerk.
FROM node:24-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Vite bakes VITE_* into the bundle at BUILD time, so this is the URL the
# BROWSER will use -- not a URL resolved inside the compose network. It has to
# be an address reachable from the user's machine, which is why it defaults to
# the published localhost port and not to `http://backend:8000`.
#
# Left empty, the app runs on its built-in demo dataset instead and badges
# every surface that renders it, which is a working demo rather than a broken
# page. That is a deliberate fallback, not an accident.
# `localhost` and not 127.0.0.1: the backend's `cors_origins` defaults to
# `http://localhost:8080`, so the dashboard must be opened on that exact
# origin, and the API it calls is spelled to match. Opening the app as
# `http://127.0.0.1:8080` fails CORS regardless of what is baked here.
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

# Optional. Unset, the app has no sign-in UI and the backend answers every
# caller -- which it says loudly, on startup and on the status dashboard.
ARG VITE_CLERK_PUBLISHABLE_KEY=
ENV VITE_CLERK_PUBLISHABLE_KEY=$VITE_CLERK_PUBLISHABLE_KEY

RUN npm run build

FROM node:24-slim

WORKDIR /app
COPY --from=build /app/.output ./.output

# Nitro's node-server preset reads PORT. 8080 to match the dev server, so the
# URL in the README is the same either way.
ENV PORT=8080 NODE_ENV=production
EXPOSE 8080

CMD ["node", ".output/server/index.mjs"]
