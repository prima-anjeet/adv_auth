"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "../context/auth-context";

export default function RequireAuth({
  children,
  fallback,
}: {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading && !user) {
      const nextParam = pathname ? `?next=${encodeURIComponent(pathname)}` : "";
      router.replace(`/login${nextParam}`);
    }
  }, [loading, user, router, pathname]);

  if (loading) {
    return fallback ?? <p className="text-sm text-gray-400">Loading...</p>;
  }

  if (!user) {
    return null;
  }

  return <>{children}</>;
}
