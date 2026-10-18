import { defineConfig } from "vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { nitro } from "nitro/vite";

export default defineConfig({
  server: {
    port: 8080,
    host: true,
  },
  plugins: [
    tailwindcss(),
    // Redirect TanStack Start's bundled server entry to src/server.ts (the SSR
    // error wrapper); nitro builds the deployable output from it.
    tanstackStart({ server: { entry: "server" } }),
    nitro(),
    viteReact(),
  ],
  resolve: {
    // `@/` imports, from tsconfig.json's `paths`. Native since Vite 8; this was
    // the vite-tsconfig-paths plugin.
    tsconfigPaths: true,
    // React and the TanStack packages must resolve to a single copy, or hooks
    // and router context break across the SSR/client boundary.
    dedupe: [
      "react",
      "react-dom",
      "@tanstack/react-router",
      "@tanstack/react-store",
      "@tanstack/react-query",
    ],
  },
});
