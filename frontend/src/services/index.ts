import { FastAPIProvider } from "./fastapiProvider";
import type { DataProvider } from "./provider";

/** The backend at VITE_API_BASE_URL (default http://localhost:8000). */
export const provider: DataProvider = FastAPIProvider;

export * from "./provider";
export { API_BASE_URL, ApiError, endpoints, AUTH_CONFIGURED } from "./api";
