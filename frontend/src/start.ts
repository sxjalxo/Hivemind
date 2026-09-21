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
export const startInstance = createStart(() => ({
  requestMiddleware: [errorMiddleware, clerkMiddleware(), csrfMiddleware],
}));
