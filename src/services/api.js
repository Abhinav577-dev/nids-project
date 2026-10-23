
const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"
).replace(/\/+$/, "");

// True only when explicitly enabled in the frontend environment.
export const DEMO_MODE =
  import.meta.env.VITE_DEMO_MODE !== "false";

async function request(endpoint) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(
      `API request failed: ${response.status} ${response.statusText}`
    );
  }

  return response.json();
}

export const api = {
  health: () => request("/api/health"),
  overview: () => request("/api/overview"),
  flows: () => request("/api/flows"),
  predictions: () => request("/api/predictions"),
  alerts: () => request("/api/alerts"),
  analytics: () => request("/api/analytics"),
  pipeline: () => request("/api/pipeline"),
};
