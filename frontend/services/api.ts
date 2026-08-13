import axios from "axios";

const apiClient = axios.create({
  baseURL: "/api",
});

apiClient.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("token");
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error?.config;
    const status = error?.response?.status;
    const method = String(config?.method || "get").toLowerCase();
    const retryable = method === "get" && (!error.response || status >= 500);
    const retries = Number(config?._retryCount || 0);

    if (config && retryable && retries < 2) {
      config._retryCount = retries + 1;
      await new Promise((resolve) => setTimeout(resolve, 500 * config._retryCount));
      return apiClient(config);
    }

    return Promise.reject(error);
  },
);

export default apiClient;
