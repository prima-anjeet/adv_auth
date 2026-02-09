"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "./context/auth-context";

export default function Home() {
  const { user, loading, signOut } = useAuth();
  const router = useRouter();

  const handleLogout = async () => {
    await signOut();
    router.replace("/");
  };

  return (
    <div className="flex flex-col min-h-screen items-center justify-center bg-gray-900 text-white">
      <h1 className="text-5xl font-bold mb-8">Welcome to Advanced Auth</h1>
      <p className="text-lg mb-8">
        Your secure and modern authentication solution.
      </p>

      {!loading && user ? (
        <div className="flex items-center gap-4">
          <Link
            href="/dashboard"
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-md text-lg font-semibold transition"
          >
            Dashboard
          </Link>
          <button
            type="button"
            onClick={handleLogout}
            className="px-6 py-2 bg-gray-700 hover:bg-gray-800 rounded-md text-lg font-semibold transition"
          >
            Logout
          </button>
        </div>
      ) : (
        <div className="space-x-4">
          <Link
            href="/login"
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-md text-lg font-semibold transition"
          >
            Login
          </Link>
          <Link
            href="/register"
            className="px-6 py-2 bg-gray-700 hover:bg-gray-800 rounded-md text-lg font-semibold transition"
          >
            Register
          </Link>
        </div>
      )}
    </div>
  );
}
