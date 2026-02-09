"use client";
import Link from "next/link";
import RequireGuest from "@/app/components/require-guest";
import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import { verifyEmail } from "@/app/services/auth.services";
import { showToast } from "nextjs-toast-notify";

export default function VerifyEmailPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const paramToken =
    typeof params?.token === "string"
      ? params.token
      : Array.isArray(params?.token)
      ? params.token[0]
      : null;
  const queryToken = searchParams?.get("token");
  const token = (paramToken || queryToken || "").trim();

  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">(
    token ? "loading" : "idle"
  );
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("idle");
      setMessage("");
      return;
    }

    let isActive = true;
    setStatus("loading");
    setMessage("");

    verifyEmail(token)
      .then((response) => {
        if (!isActive) return;
        const successMessage =
          response?.message ||
          "Email verified successfully. You can now log in.";
        setStatus("success");
        setMessage(successMessage);
        showToast.success(successMessage);
      })
      .catch((error: any) => {
        if (!isActive) return;
        const errorMessage =
          error?.response?.data?.message ||
          "Verification failed. The link may be invalid or expired.";
        setStatus("error");
        setMessage(errorMessage);
        showToast.error(errorMessage);
      });

    return () => {
      isActive = false;
    };
  }, [token]);

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg text-center">
          <h1 className="text-3xl font-bold">Verify Your Email</h1>
          {status === "idle" && (
            <p className="text-gray-400">
              A verification link has been sent to your email address. Please
              check your inbox and click the link to activate your account.
            </p>
          )}
          {status === "loading" && (
            <p className="text-gray-400" aria-live="polite">
              Verifying your email...
            </p>
          )}
          {status === "success" && (
            <p className="text-green-400" aria-live="polite">
              {message}
            </p>
          )}
          {status === "error" && (
            <p className="text-red-400" aria-live="polite">
              {message}
            </p>
          )}
          <div className="pt-2 flex items-center justify-center gap-3">
            {status === "success" && (
              <Link
                href="/login"
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition"
              >
                Go to Login
              </Link>
            )}
            {status === "error" && (
              <Link
                href="/register"
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-md font-semibold transition"
              >
                Register Again
              </Link>
            )}
            {status === "idle" && (
              <Link
                href="/login"
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-md font-semibold transition"
              >
                Back to Login
              </Link>
            )}
          </div>
        </div>
      </div>
    </RequireGuest>
  );
}
