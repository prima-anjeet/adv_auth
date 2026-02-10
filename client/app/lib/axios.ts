import axios, { AxiosHeaders, type AxiosRequestConfig } from "axios";

const backendUrl =
  process.env.NEXT_PUBLIC_BACKEND_URL ||
  process.env.BACKEND_URL ||
  "https://adv-auth0.onrender.com";

const axiosInstance = axios.create({
    baseURL: backendUrl,
    headers: {
        "Content-Type": "application/json",
    },
    withCredentials: true, // Include cookies in requests
});

let isRefreshing = false;
let refreshPromise: Promise<void> | null = null;

const getCookie = (name: string) => {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(
    new RegExp(`(^| )${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]+)`)
  );
  return match ? decodeURIComponent(match[2]) : null;
};

axiosInstance.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  const isSafeMethod = method === "get" || method === "head" || method === "options";

  if (!isSafeMethod) {
    const csrfToken = getCookie("csrfToken");
    if (csrfToken) {
      const headers = AxiosHeaders.from(config.headers);
      headers.set("x-csrf-token", csrfToken);
      config.headers = headers;
    }
  }

  return config;
});

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error?.config as AxiosRequestConfig & {
      _retry?: boolean;
      _csrfRetry?: boolean;
    };
    const status = error?.response?.status;
    const errorCode = error?.response?.data?.code;

    if (!originalRequest || status === undefined) {
      return Promise.reject(error);
    }

    const isAuthError = status === 401 || status === 403;
    const isRefreshCall =
      typeof originalRequest?.url === "string" &&
      originalRequest.url.includes("/refresh-token");
    const isCsrfRefreshCall =
      typeof originalRequest?.url === "string" &&
      originalRequest.url.includes("/refresh-csrf");

    const isCsrfError =
      status === 403 &&
      (errorCode === "CSRF_TOKEN_MISSING" ||
        errorCode === "CSRF_TOKEN_EXPIRED" ||
        errorCode === "CSRF_TOKEN_INVALID");

    if (isCsrfError && !isCsrfRefreshCall && !originalRequest._csrfRetry) {
      originalRequest._csrfRetry = true;
      try {
        await axios.post(
          `${backendUrl}/api/v1/refresh-csrf`,
          {},
          { withCredentials: true }
        );
        return axiosInstance(originalRequest);
      } catch (csrfRefreshError) {
        return Promise.reject(csrfRefreshError);
      }
    }

    if (!isAuthError || isRefreshCall || originalRequest._retry) {
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    try {
      if (!isRefreshing) {
        isRefreshing = true;
        refreshPromise = axios
          .get(`${backendUrl}/api/v1/refresh-token`, {
            withCredentials: true,
          })
          .then(() => undefined)
          .finally(() => {
            isRefreshing = false;
          });
      }

      if (refreshPromise) {
        await refreshPromise;
      }

      return axiosInstance(originalRequest);
    } catch (refreshError) {
      return Promise.reject(refreshError);
    }
  }
);

export default axiosInstance;
