import { create } from "zustand";

interface AuthState {
  token: string | null;
  username: string | null;
  setToken: (token: string) => void;
  setUser: (username: string) => void;
  logout: () => void;
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: localStorage.getItem("dc_token"),
  username: localStorage.getItem("dc_username"),
  setToken: (token) => {
    localStorage.setItem("dc_token", token);
    set({ token });
  },
  setUser: (username) => {
    localStorage.setItem("dc_username", username);
    set({ username });
  },
  logout: () => {
    localStorage.removeItem("dc_token");
    localStorage.removeItem("dc_username");
    set({ token: null, username: null });
  },
  isAuthenticated: () => !!get().token,
}));
