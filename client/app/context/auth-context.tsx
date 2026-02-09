"use client";

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { getMyProfile, logout } from "../services/auth.services";
import type { User } from "../types";

type AuthContextValue = {
  user: User | null;
  loading: boolean;
  setUser: (user: User | null) => void;
  refreshProfile: () => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshProfile = async () => {
    setLoading(true);
    try {
      const response = await getMyProfile();
      if (response?.user) {
        setUser(response.user);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const signOut = async () => {
    try {
      await logout();
    } catch {
      // ignore logout errors
    } finally {
      setUser(null);
    }
  };

  useEffect(() => {
    refreshProfile();
  }, []);

  const value = useMemo(
    () => ({ user, loading, setUser, refreshProfile, signOut }),
    [user, loading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
