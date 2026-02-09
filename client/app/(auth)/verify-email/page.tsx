"use client";
import RequireGuest from "@/app/components/require-guest";

export default function VerifyEmailPage() {
  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg text-center">
          <h1 className="text-3xl font-bold">Verify Your Email</h1>
          <p className="text-gray-400">
            A verification link has been sent to your email address. Please check
            your inbox and click the link to activate your account.
          </p>
        </div>
      </div>
    </RequireGuest>
  );
}


