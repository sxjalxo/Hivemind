import { DEMO_MODE } from "./api";
import { DemoProvider } from "./demo/demoProvider";
import { FastAPIProvider } from "./fastapiProvider";
import type { DataProvider } from "./provider";

/**
 * Single switch point: DemoProvider -> FastAPIProvider.
 * Set VITE_API_BASE_URL to move the whole app onto the real backend.
 */
export const provider: DataProvider = DEMO_MODE ? DemoProvider : FastAPIProvider;

export const isDemoMode = provider.mode === "demo";

export { DemoProvider, FastAPIProvider };
export * from "./provider";
export { API_BASE_URL, ApiError, endpoints } from "./api";
