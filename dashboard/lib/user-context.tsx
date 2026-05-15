"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, type User } from "@/lib/api";
import { errorMessage } from "@/lib/format";

interface UserContextValue {
  user: User | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  setUser: (u: User) => void;
}

const UserContext = createContext<UserContextValue | null>(null);

// UserProvider centralises the `/v1/me` fetch so the dashboard shell, topbar
// and every page share a single in-flight request instead of refetching the
// same profile on every navigation.
export function UserProvider({ children }: { children: ReactNode }) {
  const [user, setUserState] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const u = await api<User>("/v1/me");
      setUserState(u);
    } catch (e) {
      setError(errorMessage(e, "Failed to load profile"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    api<User>("/v1/me")
      .then((u) => {
        if (!cancelled) {
          setUserState(u);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (cancelled) return;
        setError(errorMessage(e, "Failed to load profile"));
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <UserContext.Provider
      value={{ user, loading, error, refresh, setUser: setUserState }}
    >
      {children}
    </UserContext.Provider>
  );
}

export function useUser(): UserContextValue {
  const ctx = useContext(UserContext);
  if (!ctx) {
    throw new Error("useUser must be used within <UserProvider>");
  }
  return ctx;
}
