"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../context/auth-context";

export default function RequireGuest({
  children,
  redirectTo = "/",
  fallback,
}: {
  children: React.ReactNode;
  redirectTo?: string;
  fallback?: React.ReactNode;
}) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && user) {
      router.replace(redirectTo);
    }
  }, [loading, user, router, redirectTo]);

  if (loading) {
    return fallback ?? <p className="text-sm text-gray-400">Loading...</p>;
  }

  if (user) {
    return null;
  }

  return <>{children}</>;
}
