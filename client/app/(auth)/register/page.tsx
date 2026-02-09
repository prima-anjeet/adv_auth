
"use client";
import Link from "next/link";
import { useState } from "react";
import RequireGuest from "@/app/components/require-guest";

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    // Handle registration logic here
    console.log({ username, email, password });
  };

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
          <div className="text-center">
            <h1 className="text-3xl font-bold">Create an Account</h1>
            <p className="text-gray-400">Join us and start your journey</p>
          </div>
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label
                htmlFor="username"
                className="text-sm font-medium block mb-2"
              >
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Your username"
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label htmlFor="email" className="text-sm font-medium block mb-2">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="m@example.com"
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="password"
                className="text-sm font-medium block mb-2"
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <button
              type="submit"
              className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition"
            >
              Create an account
            </button>
          </form>
          <div className="mt-4 text-center text-sm text-gray-400">
            Already have an account?{" "}
            <Link href="/login" className="underline hover:text-blue-400">
              Sign in
            </Link>
          </div>
        </div>
      </div>
    </RequireGuest>
  );
}
