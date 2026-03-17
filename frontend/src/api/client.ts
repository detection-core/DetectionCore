import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  timeout: 30_000,
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("dc_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("dc_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  }
);

export default api;
