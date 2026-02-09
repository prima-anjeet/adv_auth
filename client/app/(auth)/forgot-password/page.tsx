
"use client";
import { forgotPassword } from "@/app/services/auth.services";
import Link from "next/link";
import { useState } from "react";
import { z } from "zod";
import { forgotPasswordSchema } from "@/app/lib/zod";
import { FormErrors } from "@/app/components/form-errors";
import { showToast } from "nextjs-toast-notify";
import RequireGuest from "@/app/components/require-guest";

type FormData = z.infer<typeof forgotPasswordSchema>;

export default function ForgotPasswordPage() {
  const [formData, setFormData] = useState<FormData>({ email: "" });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<z.ZodError | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const result = forgotPasswordSchema.safeParse(formData);
    if (!result.success) {
      setErrors(result.error);
      return;
    }
    setErrors(null);
    setIsLoading(true);
    try {
      const response = await forgotPassword(result.data);
      setSuccessMessage(response.message);
      showToast.success(response.message);
      setFormData({ email: "" });
    } catch (error: any) {
      showToast.error(error.response?.data?.message || "Request failed");
    } finally {
      setIsLoading(false);
    }
  };

  const formattedErrors = errors?.format();

  return (
    <RequireGuest>
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white">
        <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-lg shadow-lg">
          <div className="text-center">
            <h1 className="text-3xl font-bold">Forgot Password</h1>
            <p className="text-gray-400">Enter your email to reset password</p>
          </div>
          
          {successMessage ? (
              <div className="p-4 bg-green-900/50 border border-green-500 rounded text-center">
                  <p className="text-green-200">{successMessage}</p>
                  <Link href="/login" className="text-blue-400 hover:text-blue-300 text-sm mt-4 inline-block">Back to Login</Link>
              </div>
          ) : (
            <form className="space-y-6" onSubmit={handleSubmit} noValidate>
                <div>
                <label htmlFor="email" className="text-sm font-medium block mb-2">
                    Email
                </label>
                <input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) =>
                    setFormData({ ...formData, email: e.target.value })
                    }
                    placeholder="m@example.com"
                    required
                    className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                {formattedErrors?.email?._errors && (
                    <FormErrors errors={formattedErrors.email._errors} />
                )}
                </div>
                
                <button
                type="submit"
                className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-md font-semibold transition cursor-pointer"
                disabled={isLoading}
                >
                {isLoading ? "Sending..." : "Send Reset Link"}
                </button>

                <div className="text-center text-sm text-gray-400">
                    Remember your password?{" "}
                    <Link href="/login" className="text-blue-400 hover:text-blue-300">
                        Login
                    </Link>
                </div>
            </form>
          )}
        </div>
      </div>
    </RequireGuest>
  );
}
