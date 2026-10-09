import { clerkMiddleware } from "@clerk/tanstack-react-start/server";
import { createStart, createCsrfMiddleware, createMiddleware } from "@tanstack/react-start";

import { renderErrorPage } from "./lib/error-page";

const errorMiddleware = createMiddleware().server(async ({ next }) => {
  try {
    return await next();
  } catch (error) {
    if (error != null && typeof error === "object" && "statusCode" in error) {
      throw error;
    }
    console.error(error);
    return new Response(renderErrorPage(), {
      status: 500,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
});

// Start installs this automatically when src/start.ts is absent; defining the
// file opts out, so re-add it explicitly to keep server functions protected
// from cross-site requests.
const csrfMiddleware = createCsrfMiddleware({
  filter: (ctx) => ctx.handlerType === "serverFn",
});

// `clerk init` added the import but could not register it: it scaffolds for a
// project with no src/start.ts, and this one already defines its own
// requestMiddleware array. An unused import is the visible half of that; the
// invisible half is that `auth()` and every server-side Clerk helper throw
// "clerkMiddleware is not configured" without this line.
//
// Order: errorMiddleware stays outermost so it still catches anything Clerk
// throws. CSRF stays last -- it rejects cross-site server-function calls and
// does not need auth context to do it.
// Clerk's middleware THROWS at request time when no secret key is set --
// "Clerk: no secret key provided" -- which turns every page into a 500 rather
// than an unauthenticated one. That is the opposite of how the backend
// behaves: with `CLERK_ISSUER` unset it answers every caller and says so
// loudly, on startup and on the status dashboard, because an open API bound
// to localhost is the configuration this project ships for a local install.
//
// A frontend that refuses to render without the author's Clerk credentials
// cannot be distributed at all, so the middleware is installed only when
// there is a key for it to use. Nothing in this app calls `auth()` or any
// other server-side Clerk helper, so its absence costs nothing here; if
// something ever does, it must check this same condition.
//
// The sign-in UI is driven separately by VITE_CLERK_PUBLISHABLE_KEY, and the
// backend remains the only thing that actually enforces access -- it answers
// 403 regardless of what the client rendered.
const clerkConfigured = Boolean(process.env["CLERK_SECRET_KEY"]);

export const startInstance = createStart(() => ({
  requestMiddleware: clerkConfigured
    ? [errorMiddleware, clerkMiddleware(), csrfMiddleware]
    : [errorMiddleware, csrfMiddleware],
}));
